#!/usr/bin/env python3
"""Stage a narrow routed-IPv4 safety patch for the existing legacy 8787 Web UI.

This is NOT the standalone development app.js. Stage copies from the running
Web source, never the live files, no service reload or network changes.
The patch adds an authenticated read-only allocations API, prevents per-port
NAT on already-routed /32 *before* the legacy mutation code, and corrects
existing UI labels in-place when a verified GET returns them.

Fail closed on unrecognized handler/nav/render shapes. Source bytes must be
reviewed against the real OVH version before the signed release is built.
"""
from __future__ import annotations
import argparse
import ast
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import json

class LiveUIError(ValueError):
    pass

BACKEND_HELPERS = '''
def cerato_routed_allocations():
    # Uses only the existing narrowly-allowed root IP status helper.
    try:
        return cerato_summarize_ipv4(additional_ipctl('status'))
    except CeratoRoutedUIError:
        raise UserError('Attributions IPv4 incohérentes : actualisation refusée.')

def cerato_reject_routed_nat(public_ip):
    # Must execute BEFORE invoking the legacy NAT handler/controller.
    data=cerato_routed_allocations()
    if any(row['mode']=='routed-wg' and row['ip']==str(public_ip)
           for row in data['entries']):
        raise UserError('Cette IPv4 est entièrement routée vers une machine : '
                        'le NAT par port est interdit. Gère les ports sur le pare-feu du Dell.')
'''

JS_OVERLAY = r"""
let ceratoIPv4Allocations=null,ceratoIPv4Loading=false,ceratoIPv4Failure='';
async function ceratoLoadIPv4Allocations(){
  if(ceratoIPv4Loading)return;
  ceratoIPv4Loading=true;
  try{
    const d=await req('/api/ip/allocations');
    if(d.schema!=='cerato-ipv4-allocations-v1'||!Array.isArray(d.entries))
      throw Error('Réponse des allocations non reconnue');
    ceratoIPv4Allocations=d;
    ceratoIPv4Failure='';
  }catch(e){
    ceratoIPv4Allocations=null;
    ceratoIPv4Failure='Attributions IPv4 indisponibles : '+(e.message||'lecture impossible');
  }finally{
    ceratoIPv4Loading=false;
    if(['overview','ips','nat'].includes(screen))render();
  }
}
function ceratoEnhanceIPv4(){
  if(!['overview','ips','nat'].includes(screen))return;
  const data=ceratoIPv4Allocations;
  const base=document.querySelector('main')||document.getElementById('app');
  if(!base)return;
  const old=document.getElementById('cerato-routed-ip-summary');
  if(old)old.remove();
  const note=document.createElement('div');
  note.id='cerato-routed-ip-summary';
  note.setAttribute('role','status');
  note.style.cssText='border:1px solid #314457;border-radius:8px;padding:11px 14px;margin:10px 0;background:#172229;color:#d7e6ef;font-size:13px;';
  if(!data){
    note.textContent=ceratoIPv4Failure||'Vérification des affectations IPv4 en cours…';
    base.prepend(note);
    return;
  }
  note.textContent='IPv4 publiques : '+data.allocated_count+' attribuée(s), '+
       data.routed_count+' routée(s) via WireGuard, '+data.available_count+
       ' libre(s). Les IPv4 routées ne sont pas des publications NAT.';
  base.prepend(note);
  const routed=new Map(data.entries.filter(row=>row.mode==='routed-wg')
                                    .map(row=>[row.ip,row]));
  if(screen==='ips'){
    for(const tr of document.querySelectorAll('tr')){
      const cells=[...tr.querySelectorAll('td')];
      if(!cells.length)continue;
      const row=routed.get(cells[0].textContent.trim());
      if(!row)continue;
      if(cells.length>1)cells[1].textContent=row.state==='warning'
        ? 'Conflit réseau à vérifier'
        : 'Routée → '+row.peer;
      for(const control of tr.querySelectorAll('button')){
        if(/retirer du pool/i.test(control.textContent)){
          control.disabled=true;
          control.title='IPv4 affectée à une machine — retrait interdit';
          control.textContent='Attribuée';
        }
      }
    }
  }
  if(screen==='nat'){
    if(routed.size){
      for(const el of base.querySelectorAll('p,div,aside')){
        if(el.children.length===0 && el.textContent.includes('Une règle NAT redirige un port vers WireGuard.')){
          el.textContent='Les IPv4 déjà routées vers une machine ne sont pas des publications NAT. '
            +'Pour les exposer, gère les ports dans le pare-feu de la machine cible. '
            +'Le NAT par port reste réservé aux autres IPv4 non routées.';
          break;
        }
      }
    }
    for(const option of document.querySelectorAll('select option')){
      if(routed.has(option.value.trim())||routed.has(option.textContent.trim())){
        option.disabled=true;
        option.title='IPv4 routée — NAT par port indisponible';
      }
    }
  }
}
"""

def _inline_model(model: str) -> str:
    expected="from __future__ import annotations\n"
    if model.count(expected)!=1 or "def summarize(" not in model:
        raise LiveUIError("Modèle IP source inattendu")
    content=model.replace(expected,"",1)
    renames={"RoutedUIError":"CeratoRoutedUIError",
             "PEER_RE":"CERATO_ROUTED_PEER_RE",
             "_ipv4":"cerato_ui_ipv4",
             "summarize":"cerato_summarize_ipv4"}
    for old,new in renames.items():
        content=re.sub(r"\b"+re.escape(old)+r"\b",new,content)
    tree=ast.parse(content)
    if not any(isinstance(n,ast.FunctionDef) and
               n.name=="cerato_summarize_ipv4" for n in tree.body):
        raise LiveUIError("Résumé d'attribution non reconnu")
    return content

LIVE_BACKEND_SHA256="9c7087a1eeca7e3c8a4462c2cd8e6659e4d692409771117c575cd00b46b30360"
LIVE_FRONTEND_SHA256="cfadd7e7f05cc80c0f4c66c313634f8a4dd8a59549cbcbea1615437c3758aa4b"


def _is_branch(node,route):
    if not isinstance(node,ast.If):
        return False
    comp=node.test
    return (
        isinstance(comp,ast.Compare)
        and isinstance(comp.left,ast.Name) and comp.left.id=="p"
        and len(comp.ops)==1 and isinstance(comp.ops[0],ast.Eq)
        and len(comp.comparators)==1
        and isinstance(comp.comparators[0],ast.Constant)
        and comp.comparators[0].value==route
    )


def _guard(node,write):
    if not isinstance(node,ast.If):
        return False
    test=node.test
    if not (isinstance(test,ast.UnaryOp) and isinstance(test.op,ast.Not)
            and isinstance(test.operand,ast.Call)):
        return False
    call=test.operand
    if not (isinstance(call.func,ast.Attribute)
            and isinstance(call.func.value,ast.Name)
            and call.func.value.id=="self"
            and call.func.attr=="check_session"):
        return False
    if (len(call.keywords)!=1 if write else len(call.keywords)!=0):
        return False
    if write and not any(k.arg=="write" and isinstance(k.value,ast.Constant)
                         and k.value.value is True for k in call.keywords):
        return False
    return bool(node.body and isinstance(node.body[0],(ast.Return,ast.Raise)))


def _body_read(node):
    if not isinstance(node,ast.Assign) or len(node.targets)!=1:
        return False
    target=node.targets[0]
    call=node.value
    return (isinstance(target,ast.Name) and target.id=="b"
            and isinstance(call,ast.Call)
            and isinstance(call.func,ast.Attribute)
            and isinstance(call.func.value,ast.Name)
            and call.func.value.id=="self"
            and call.func.attr=="read_body")


def _reachable_method_nodes(cls,root):
    methods={n.name:n for n in cls.body if isinstance(n,ast.FunctionDef)}
    if root not in methods:
        return set()
    stack=[root]
    reached=set()
    while stack:
        name=stack.pop()
        if name in reached:
            continue
        reached.add(name)
        if len(reached)>64:
            raise LiveUIError("Délégation du handler trop large")
        for child in ast.walk(methods[name]):
            if (isinstance(child,ast.Call)
                    and isinstance(child.func,ast.Attribute)
                    and isinstance(child.func.value,ast.Name)
                    and child.func.value.id=="self"
                    and child.func.attr in methods):
                stack.append(child.func.attr)
    return reached


def _find_protected_branch(source,tree,verb,route,*,write):
    """Only a top-level branch in a reachable helper with a dominating auth gate.

    We intentionally refuse an unrecognized nested authorization flow.
    This is a static gate, never proof of runtime session or CSRF safety.
    """
    found=[]
    for cls in (n for n in ast.walk(tree) if isinstance(n,ast.ClassDef)):
        reachable=_reachable_method_nodes(cls,"do_"+verb)
        for method in cls.body:
            if not isinstance(method,ast.FunctionDef) or method.name not in reachable:
                continue
            statements=method.body
            matches=[n for n in ast.walk(method) if _is_branch(n,route)]
            for branch in matches:
                def contains(outer,inner):
                    return any(child is inner for child in ast.walk(outer))
                roots=[(idx,node) for idx,node in enumerate(statements)
                       if contains(node,branch)]
                if len(roots)!=1:
                    raise LiveUIError("Arbre des branches HTTP ambigu")
                index,root=roots[0]
                # A top-level if/elif chain is allowed. A nested conditional,
                # try, loop or match inside the route's parent is rejected.
                if not isinstance(root,ast.If):
                    raise LiveUIError("Branche API NAT imbriquée non reconnue")
                chain=root
                while chain is not branch and len(chain.orelse)==1 and isinstance(chain.orelse[0],ast.If):
                    chain=chain.orelse[0]
                if chain is not branch:
                    raise LiveUIError("Branche HTTP non directement accessible")
                guards=[n for n in statements[:index] if _guard(n,write)]
                if len(guards)!=1:
                    raise LiveUIError("Garde d'authentification avant route absent ou ambigu")
                if write and len([n for n in statements[:index] if _body_read(n)])!=1:
                    raise LiveUIError("Lecture du formulaire avant route absente ou ambiguë")
                if branch.end_lineno is None or not branch.body or (
                    write and branch.body[0].lineno<=branch.lineno
                ):
                    raise LiveUIError("Branche HTTP compacte non patchable")
                found.append(branch)
    if len(found)!=1:
        raise LiveUIError("Branche HTTP authentifiée introuvable ou dupliquée : "+route)
    return found[0]


def _inject_after_branch_line(source,branch,guard_call):
    lines=source.splitlines(keepends=True)
    line=lines[branch.lineno-1]
    if (branch.col_offset<0 or branch.col_offset>32
            or not line.startswith(" "*branch.col_offset)
            or "\n" not in line
            or not re.match(r"^\s*(?:if|elif)\s+p\s*==\s*(['\"])(/api/[a-z/]+)\1\s*:\s*$",
                            line.rstrip("\r\n"))):
        raise LiveUIError("Syntaxe physique du handler HTTP inattendue")
    indent=" "*(branch.col_offset+4)
    lines.insert(branch.lineno,indent+guard_call+"\n")
    return "".join(lines)


def patch_backend(source: str, model: str) -> str:
    if (source.count("def additional_ipctl(")!=1 or
            source.count("def netstate():")!=1 or
            "def cerato_routed_allocations(" in source):
        raise LiveUIError("Backend Additional IPv4 incompatible ou déjà corrigé")
    original=ast.parse(source)
    nat=_find_protected_branch(source,original,"POST","/api/nat/add",write=True)
    # The removed route is NOT changed: keep existing NAT unpublish semantics.
    remove=_find_protected_branch(source,original,"POST","/api/nat/remove",write=True)
    get=_find_protected_branch(source,original,"GET","/api/status",write=False)
    if nat.lineno==remove.lineno or get.lineno==nat.lineno:
        raise LiveUIError("Dispatch API incompatible")
    # Inject from bottom upwards to preserve original source line positions.
    inserts=sorted([(nat,'cerato_reject_routed_nat(b.get("public_ip") or b.get("ip"))'),
                    (get,'return self.send_json(200,cerato_routed_allocations()) if p=="/api/ip/allocations" else None')],
                   key=lambda pair:pair[0].lineno,reverse=True)
    for branch,call in inserts:
        if branch is get:
            # Insert a new sibling branch *before* the existing /api/status
            # route, not inside it, so /api/ip/allocations is reachable.
            lines=source.splitlines(keepends=True)
            original_line=lines[branch.lineno-1]
            indent=" "*branch.col_offset
            lines.insert(branch.lineno-1,
                         indent+"if p=='/api/ip/allocations': return self.send_json(200,cerato_routed_allocations())\n")
            source="".join(lines)
        else:
            source=_inject_after_branch_line(source,branch,call)
    anchor="def netstate():"
    injected=_inline_model(model)+"\n"+BACKEND_HELPERS+"\n"
    if source.count(anchor)!=1:
        raise LiveUIError("Point d'insertion de la lecture réseau ambigu")
    source=source.replace(anchor,injected+anchor,1)
    ast.parse(source)
    if source.count("cerato_reject_routed_nat(b.get")!=1 or source.count("'/api/ip/allocations'")!=1:
        raise LiveUIError("Injection Web incohérente")
    return source


def patch_frontend(source: str) -> str:
    render_anchor="function render(){if(!live)return;"
    if (source.count(render_anchor)!=1 or
            "function bind(" not in source or
            "function updates(){" not in source or
            "function ceratoEnhanceIPv4()" in source):
        raise LiveUIError("UI legacy inattendue ou patch déjà installé")
    instrument="""function render(){if(!live)return;
  if(['overview','ips','nat'].includes(screen)){
    if(!ceratoIPv4Allocations&&!ceratoIPv4Loading&&!ceratoIPv4Failure)
      Promise.resolve().then(ceratoLoadIPv4Allocations);
    Promise.resolve().then(ceratoEnhanceIPv4);
  }
"""
    updated=source.replace(render_anchor,JS_OVERLAY+"\n"+instrument,1)
    return updated

def stage(source: Path,destination: Path,model: Path,*,
          expected_backend_sha=LIVE_BACKEND_SHA256,
          expected_frontend_sha=LIVE_FRONTEND_SHA256):
    if source.resolve()==destination.resolve() or destination.exists():
        raise LiveUIError("Staging doit être distinct et absent")
    backend=source/"backend/server.py"
    frontend=source/"web/app.js"
    if any(p.is_symlink() or not p.is_file() for p in (backend,frontend,model)):
        raise LiveUIError("Fichiers source absents ou symboliques")
    if backend.stat().st_size>300_000 or frontend.stat().st_size>300_000:
        raise LiveUIError("Source Web de taille inattendue")
    import hashlib
    if hashlib.sha256(backend.read_bytes()).hexdigest()!=expected_backend_sha:
        raise LiveUIError("Empreinte du backend OVH non reconnue : staging interdit")
    if hashlib.sha256(frontend.read_bytes()).hexdigest()!=expected_frontend_sha:
        raise LiveUIError("Empreinte du frontend OVH non reconnue : staging interdit")
    code=patch_backend(backend.read_text(encoding="utf8"),model.read_text(encoding="utf8"))
    ui=patch_frontend(frontend.read_text(encoding="utf8"))
    with tempfile.TemporaryDirectory(prefix="cerato-ui-verify-") as temp:
        a=Path(temp)/"server.py"
        b=Path(temp)/"app.js"
        a.write_text(code,encoding="utf8")
        b.write_text(ui,encoding="utf8")
        subprocess.run(["python3","-m","py_compile",str(a)],check=True,timeout=15)
        if shutil.which("node"):
            subprocess.run(["node","--check",str(b)],check=True,timeout=15)
    (destination/"backend").mkdir(parents=True,mode=0o700)
    (destination/"web").mkdir(mode=0o700)
    (destination/"backend/server.py").write_text(code,encoding="utf8")
    (destination/"web/app.js").write_text(ui,encoding="utf8")
    return {"status":"staged-only","production_modified":False,
            "network_modified":False,
            "routes_added":["GET /api/ip/allocations"],
            "guard":"NAT rejected before legacy handler on routed IPv4",
            "files":["backend/server.py","web/app.js"],
            "signed_release_required":True}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--destination",type=Path,required=True)
    p.add_argument("--model",type=Path,required=True)
    args=p.parse_args()
    try:
        print(json.dumps(stage(args.source,args.destination,args.model),
                         ensure_ascii=False,indent=2))
    except (LiveUIError,OSError,UnicodeError,subprocess.CalledProcessError,
            subprocess.TimeoutExpired,SyntaxError) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

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

def patch_backend(source: str, model: str) -> str:
    if (source.count("def additional_ipctl(")!=1 or
            source.count("def netstate():")!=1 or
            "def cerato_routed_allocations(" in source):
        raise LiveUIError("Backend Additional IPv4 incompatible ou déjà corrigé")
    if "if not self.check_session" not in source or "write=True" not in source:
        raise LiveUIError("Protections d'authentification live non retrouvées")
    if "b=self.read_body()" not in source and "b = self.read_body()" not in source:
        raise LiveUIError("Lecture du formulaire live non reconnue")
    status_pat=re.compile(
        r"^(?P<indent> {8,24})if p=='/api/status': return self\.send_json\(200,netstate\(\)\)[ \t]*$",
        re.M)
    status=list(status_pat.finditer(source))
    if len(status)!=1:
        raise LiveUIError("Handler GET status live introuvable")
    # Ensure the inserted read-only API is behind the same session check as
    # GET /api/status, not merely that a check exists elsewhere in the file.
    get_head=source.rfind("    def do_GET(self):",0,status[0].start())
    get_tail=source.rfind("    def do_POST(self):",0,status[0].start())
    if get_head<0 or get_tail>get_head:
        raise LiveUIError("Handler GET authentifié non vérifiable")
    get_prefix=source[get_head:status[0].start()]
    if not re.search(r"if not self\.check_session\(\):",get_prefix):
        raise LiveUIError("Protection de session avant GET status non vérifiable")
    get=status[0].group(0)
    indent=status[0].group("indent")
    new_get=indent+"if p=='/api/ip/allocations': return self.send_json(200,cerato_routed_allocations())\n"+get
    source=source.replace(get,new_get,1)
    # Match exactly ONE NAT handler; do not guess API changes.
    natpat=re.compile(r"^(?P<indent> {8,24})if p=='/api/nat(?:/add)?':[ \t]*$",re.M)
    matches=list(natpat.finditer(source))
    if len(matches)!=1:
        raise LiveUIError("Handler NAT live absent ou ambigu")
    post_head=source.rfind("    def do_POST(self):",0,matches[0].start())
    if post_head<0 or not re.search(
            r"if not self\.check_session\(write=True\)",source[post_head:matches[0].start()]):
        raise LiveUIError("Protection CSRF/compte avant POST NAT non vérifiable")
    nat=matches[0].group(0)
    nat_indent=matches[0].group("indent")
    next_line=nat_indent+'    cerato_reject_routed_nat(b.get("public_ip") or b.get("ip"))'
    source=source.replace(nat,nat+"\n"+next_line,1)
    # Never inject in a branch with arbitrary first statements or before auth
    # if the real AST / syntax does not validate.
    anchor="def netstate():"
    injected=_inline_model(model)+"\n"+BACKEND_HELPERS+"\n"
    source=source.replace(anchor,injected+anchor,1)
    ast.parse(source)
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

def stage(source: Path,destination: Path,model: Path):
    if source.resolve()==destination.resolve() or destination.exists():
        raise LiveUIError("Staging doit être distinct et absent")
    backend=source/"backend/server.py"
    frontend=source/"web/app.js"
    if any(p.is_symlink() or not p.is_file() for p in (backend,frontend,model)):
        raise LiveUIError("Fichiers source absents ou symboliques")
    if backend.stat().st_size>300_000 or frontend.stat().st_size>300_000:
        raise LiveUIError("Source Web de taille inattendue")
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

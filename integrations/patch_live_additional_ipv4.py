#!/usr/bin/env python3
"""Patch only Cerato's EXISTING Web backend/frontend for Additional IPv4.

Does not replace sessions, accounts, WireGuard, NAT handlers or templates.
Fail-closed anchors protect against an unknown/unverified live version.
It patches COPIES in a staging directory, not live files.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


class PatchError(Exception):
    pass


CTL_HELPER = '''
def additional_ipctl(*args):
    # A dedicated, tightly scoped root helper; no shell or arbitrary command.
    allowed = {"preview", "import-local", "status"}
    if not args or args[0] not in allowed:
        raise UserError("Action Additional IPv4 non autorisée.")
    cmd = ["sudo", "-n", "/usr/local/sbin/cerato-ipctl", *map(str, args)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise UserError("Service Additional IPv4 indisponible.")
    if result.returncode:
        raise UserError("Échec de configuration Additional IPv4. Vérifier le journal système.")
    return json.loads(result.stdout)

'''

API_HANDLER = '''            if p=='/api/ip/preview':
                ip=valid_ip(b.get('ip'),global_ip=True)
                mode=b.get('mode','local-nat')
                if mode not in ('local-nat','routed-wg'):
                    raise UserError('Mode Additional IPv4 inconnu.')
                result=additional_ipctl('preview',ip,'--mode',mode)
                return self.send_json(200,result)
            if p=='/api/ip/configure':
                ip=valid_ip(b.get('ip'),global_ip=True)
                mode=b.get('mode','local-nat')
                if mode!='local-nat':
                    raise UserError('Le routage complet requiert un agent Linux vérifié et un rollback réseau. Non activé.')
                # 1. Add the /32 locally and persist it (no interface restart).
                result=additional_ipctl('import-local',ip)
                # 2. The existing Cerato controller remains authoritative for
                # its pool, peer/NAT configuration and nftables.
                current=json.loads(ctl('status'))
                if ip not in current.get('pool',[]):
                    ctl('pool-add',ip)
                audit('additional-ip-import',f'{ip} local-nat')
                return self.send_json(200,{'ok':True,'ip':ip,
                    'message':'Additional IPv4 configurée et rendue persistante. Disponible dans le pool NAT.'})
'''

def patch_server(code: str) -> str:
    if "def additional_ipctl(" in code:
        raise PatchError("Patch Additional IPv4 déjà présent.")
    anchor="def netstate():"
    if code.count(anchor)!=1:
        raise PatchError("Backend incompatible : fonction netstate absente ou dupliquée.")
    code=code.replace(anchor,CTL_HELPER+anchor)
    point="            if p=='/api/peers':"
    if code.count(point)!=1 or "if not self.check_session(write=True)" not in code:
        raise PatchError("Backend incompatible : autorisation ou handler des pairs introuvable.")
    return code.replace(point,API_HANDLER+point)


def patch_app(code: str) -> str:
    if "/api/ip/configure" in code:
        raise PatchError("UI Additional IPv4 déjà corrigée.")
    original="if(action==='add-ip')return {title:'Importer une Additional IPv4',desc:'L’adresse doit déjà être configurée sur l’interface WAN du RISE-1.',endpoint:'/api/ip/add',fields:[['ip','IPv4 OVH additionnelle','text','']]}"
    revised="if(action==='add-ip')return {title:'Importer et configurer une Additional IPv4',desc:'Cerato détecte la WAN et configure la /32 de manière persistante. Le mode routé nécessite un agent Linux et reste désactivé tant qu’il n’est pas validé.',endpoint:'/api/ip/configure',fields:[['ip','IPv4 OVH additionnelle','text',''],['mode','Mode d’attribution','select',['local-nat','routed-wg']]]}"
    if code.count(original)!=1:
        raise PatchError("UI incompatible : formulaire d'import inattendu.")
    code=code.replace(original,revised)
    marker="try{const v=await req(def.endpoint,'POST',data);"
    if code.count(marker)!=1:
        raise PatchError("UI incompatible : envoi des formulaires inattendu.")
    change="""try{
      if(action==='add-ip'){
        const check=await req('/api/ip/preview','POST',{ip:data.ip,mode:data.mode});
        if(!check.supported)throw Error(check.reason||'Mode non disponible');
        if(!confirm('Configurer '+check.ip+'/32 sur '+check.wan+' et enregistrer sa persistance ? Les règles NAT existantes sont conservées.'))return;
      }
      const v=await req(def.endpoint,'POST',data);"""
    return code.replace(marker,change)


def patch_tree(source: Path, destination: Path):
    backend=source/"backend"/"server.py"
    app=source/"web"/"app.js"
    if not backend.is_file() or not app.is_file():
        raise PatchError("La structure du panneau actif est inconnue.")
    if source.resolve()==destination.resolve():
        raise PatchError("Il est interdit de modifier le panneau actif en place.")
    patched_server=patch_server(backend.read_text(encoding="utf8"))
    patched_app=patch_app(app.read_text(encoding="utf8"))
    # No editing on target until both files have been validated.
    (destination/"backend").mkdir(parents=True,exist_ok=True)
    (destination/"web").mkdir(parents=True,exist_ok=True)
    (destination/"backend"/"server.py").write_text(patched_server,encoding="utf8")
    (destination/"web"/"app.js").write_text(patched_app,encoding="utf8")
    return {"backend_bytes":len(patched_server),"frontend_bytes":len(patched_app)}


if __name__=="__main__":
    p=argparse.ArgumentParser(description="Cerato Network live Additional IPv4 updater")
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--destination",type=Path,required=True)
    opts=p.parse_args()
    try:
        print(patch_tree(opts.source,opts.destination))
    except (PatchError,OSError,UnicodeError) as error:
        p.error(str(error))

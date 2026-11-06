#!/usr/bin/env python3
"""Patch ONLY the routed entries in the legacy Cerato Additional IPv4 status().

The public /32 and its WireGuard route already work. This hotfix NEVER calls
ip/wg/nft/systemctl mutations and never changes any network configuration.
--check stages and validates a copy. --install backs up and atomically swaps
only /usr/local/sbin/cerato-ipctl, then checks and restores on failure.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone

LIVE=Path("/usr/local/sbin/cerato-ipctl")
CFG=Path("/etc/cerato-network/config.json")
STATE=Path("/etc/cerato-network/additional-ip-managed.json")
BACKUPS=Path("/var/backups/cerato-network-inplace/ipctl-status")
BASELINE_PREFIX="14afbb3cb5d793e1"
MARKER="# CERATO-IPCTL-ROUTED-STATUS-V1"
PATCH_CODE="""
cerato_cfg_routes=cfg.get("routed_ipv4",[])
cerato_state_routes=state.get("routed_ipv4",[])
if not isinstance(cerato_cfg_routes,list) or not isinstance(cerato_state_routes,list):
    raise IPError("Attributions routées incohérentes")
if len(cerato_cfg_routes)>256 or len(cerato_state_routes)>256:
    raise IPError("Trop d'attributions routées")
cerato_cfg_seen=set()
for cerato_item in cerato_cfg_routes:
    if not isinstance(cerato_item,dict) or set(cerato_item)!={"ip","peer"}:
        raise IPError("Configuration d'IPv4 routée invalide")
    cerato_ident=(cerato_item["ip"],cerato_item["peer"])
    if cerato_ident in cerato_cfg_seen:
        raise IPError("Attribution IPv4 dupliquée")
    cerato_cfg_seen.add(cerato_ident)
cerato_state_seen=set()
cerato_routed=[]
for cerato_item in cerato_state_routes:
    if not isinstance(cerato_item,dict) or set(cerato_item)!={"ip","peer","wan"}:
        raise IPError("État d'IPv4 routée invalide")
    cerato_ip=cerato_item["ip"]
    cerato_peer=cerato_item["peer"]
    if (not isinstance(cerato_ip,str) or not isinstance(cerato_peer,str)
            or cerato_item["wan"]!=wan or cerato_ip not in cfg["pool"]
            or cerato_ip==primary or cerato_peer not in cfg["peers"]
            or cerato_ip in active):
        raise IPError("Attribution routée incompatible avec le pool/WAN")
    if any((not isinstance(cerato_nat,dict) or
            cerato_nat.get("public_ip")==cerato_ip)
           for cerato_nat in cfg["mappings"]):
        raise IPError("NAT et IPv4 routée incompatibles")
    if any(isinstance(cerato_local,dict) and
           cerato_local.get("ip")==cerato_ip
           for cerato_local in state["local_ipv4"]):
        raise IPError("IPv4 déclarée locale et routée")
    cerato_ident=(cerato_ip,cerato_peer)
    if cerato_ident in cerato_state_seen:
        raise IPError("Attribution persistante dupliquée")
    cerato_state_seen.add(cerato_ident)
    cerato_routed.append({"ip":cerato_ip,"mode":"routed-wg",
                          "peer":cerato_peer,"present_on_wan":False})
if cerato_cfg_seen!=cerato_state_seen:
    raise IPError("Configuration routée et état persistant différents")
"""

class StatusPatchError(RuntimeError):
    pass

def patched_source(original:str,*,require_baseline:bool=True)->str:
    if MARKER in original:
        raise StatusPatchError("Le correctif est déjà présent")
    if require_baseline:
        digest=hashlib.sha256(original.encode("utf-8")).hexdigest()
        if not digest.startswith(BASELINE_PREFIX):
            raise StatusPatchError("Empreinte du contrôleur OVH inconnue")
    try:
        tree=ast.parse(original)
    except SyntaxError as exc:
        raise StatusPatchError("Contrôleur source non Python") from exc
    defs=[node for node in tree.body if isinstance(node,ast.FunctionDef)]
    functions={item.name for item in defs}
    required={"status","read_config","state_read","effective_wan","listed"}
    if not required.issubset(functions):
        raise StatusPatchError("Fonctions IPv4 historiques non reconnues")
    if not any(isinstance(node,ast.ClassDef) and node.name=="IPError"
               for node in tree.body):
        raise StatusPatchError("Erreur de contrôleur manquante")
    targets=[item for item in defs if item.name=="status"]
    if len(targets)!=1:
        raise StatusPatchError("status() absent ou dupliqué")
    function=targets[0]
    statements=[item for item in function.body if isinstance(item,ast.Return)]
    if len(statements)!=1 or function.body[-1] is not statements[0]:
        raise StatusPatchError("Retour status() inattendu")
    returned=statements[0]
    if not isinstance(returned.value,ast.Dict):
        raise StatusPatchError("Format de retour status() inconnu")
    keys=[k.value if isinstance(k,ast.Constant) else None
          for k in returned.value.keys]
    if len(keys)!=len(set(keys)) or not {"managed","pool","mappings","primary_ipv4"}.issubset(keys):
        raise StatusPatchError("Format status() incomplet")
    index=keys.index("managed")
    current=returned.value.values[index]
    if not isinstance(current,ast.ListComp):
        raise StatusPatchError("Liste managed historique inconnue")
    names={node.id for node in ast.walk(function) if isinstance(node,ast.Name)}
    if not {"cfg","wan","primary","active","state"}.issubset(names):
        raise StatusPatchError("Variables status() historiques inconnues")
    if "routed_ipv4" in ast.unparse(function):
        raise StatusPatchError("status() semble déjà prendre en charge le routage")
    returned.value.values[index]=ast.BinOp(
        left=current,op=ast.Add(),right=ast.Name(id="cerato_routed",ctx=ast.Load()))
    at=function.body.index(returned)
    function.body[at:at]=ast.parse(PATCH_CODE).body
    generated=ast.unparse(ast.fix_missing_locations(function))
    lines=original.splitlines(keepends=True)
    result=("".join(lines[:function.lineno-1])+MARKER+"\n"+
            generated+"\n"+"".join(lines[function.end_lineno:]))
    compile(result,"<cerato-ipctl-patched>","exec")
    return result

def _read_safe(path:Path)->str:
    if path.is_symlink() or not path.is_file():
        raise StatusPatchError("Contrôleur IPv4 absent ou symbolique")
    st=path.stat()
    if (st.st_uid!=0 or st.st_size>250000 or st.st_size<1000 or
            st.st_mode & (stat.S_IWGRP|stat.S_IWOTH)):
        raise StatusPatchError("Contrôleur IPv4 de permissions/taille inconnues")
    data=path.read_bytes()
    if not data.startswith(b"#!") or not os.access(path,os.X_OK):
        raise StatusPatchError("Entrée CLI IPv4 inexécutable")
    try:
        return data.decode("utf8")
    except UnicodeDecodeError as exc:
        raise StatusPatchError("Contrôleur non UTF-8") from exc

def _status(path:Path)->dict:
    p=subprocess.run([str(path),"status"],capture_output=True,
                     text=True,timeout=20,check=False)
    if p.returncode:
        raise StatusPatchError("Statut IPv4 candidat en échec")
    try:
        data=json.loads(p.stdout)
    except ValueError as exc:
        raise StatusPatchError("Statut IPv4 candidat non JSON") from exc
    if not isinstance(data,dict) or not isinstance(data.get("managed"),list):
        raise StatusPatchError("Réponse statut IPv4 invalide")
    return data

def _verify(expected:dict,result:dict):
    desired={(row["ip"],row["peer"]) for row in expected["routed_ipv4"]}
    observed={(row.get("ip"),row.get("peer"))
              for row in result["managed"] if row.get("mode")=="routed-wg"}
    if observed!=desired:
        raise StatusPatchError("Attributions routées non remontées correctement")
    if len(result.get("pool",[]))!=len(expected["pool"]):
        raise StatusPatchError("Le pool IPv4 a changé")

def _atomic(path:Path,contents:bytes,metadata):
    fd,name=tempfile.mkstemp(prefix=".cerato-ipctl-patch-",dir=path.parent)
    try:
        os.fchmod(fd,stat.S_IMODE(metadata.st_mode))
        os.fchown(fd,metadata.st_uid,metadata.st_gid)
        with os.fdopen(fd,"wb") as file:
            file.write(contents)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def execute(*,install:bool=False,live:Path=LIVE):
    if os.geteuid()!=0:
        raise StatusPatchError("Root requis")
    original=_read_safe(live)
    cfg=json.loads(CFG.read_text())
    persistent=json.loads(STATE.read_text())
    if not isinstance(cfg.get("routed_ipv4"),list) or not isinstance(persistent.get("routed_ipv4"),list):
        raise StatusPatchError("Métadonnées routées manquantes")
    if not cfg["routed_ipv4"] or not persistent["routed_ipv4"]:
        raise StatusPatchError("Aucune IPv4 routée à réparer")
    before=_status(live)
    if any(row.get("mode")=="routed-wg" for row in before["managed"]):
        raise StatusPatchError("Le contrôleur installé signale déjà des IPv4 routées")
    candidate=patched_source(original).encode("utf8")
    metadata=live.stat()
    with tempfile.TemporaryDirectory(prefix="cerato-ipctl-stage-") as temporary:
        staged=Path(temporary)/"cerato-ipctl"
        staged.write_bytes(candidate)
        os.chmod(staged,stat.S_IMODE(metadata.st_mode))
        outcome=_status(staged)
        _verify(cfg,outcome)
    if not install:
        return {"status":"staging_validated","routed_count":len(cfg["routed_ipv4"]),
                "network_modified":False,"production_modified":False}
    BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
    if BACKUPS.is_symlink() or BACKUPS.stat().st_uid!=0:
        raise StatusPatchError("Dossier de sauvegarde inconnu")
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup=BACKUPS/("cerato-ipctl-"+stamp+"-"+str(os.getpid()))
    shutil.copy2(live,backup,follow_symlinks=False)
    os.chmod(backup,0o600)
    try:
        if hashlib.sha256(live.read_bytes()).digest()!=hashlib.sha256(original.encode()).digest():
            raise StatusPatchError("Contrôleur modifié entre staging et installation")
        _atomic(live,candidate,metadata)
        _verify(cfg,_status(live))
    except BaseException:
        _atomic(live,original.encode("utf8"),metadata)
        raise
    return {"status":"installed_verified","routed_count":len(cfg["routed_ipv4"]),
            "network_modified":False,"service_restarted":False,
            "backup":str(backup)}

def main():
    p=argparse.ArgumentParser(description="Cerato live IPv4 status scoped repair")
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--check",action="store_true")
    group.add_argument("--install",action="store_true")
    args=p.parse_args()
    try:
        print(json.dumps(execute(install=args.install),sort_keys=True))
    except (StatusPatchError,OSError,ValueError,KeyError,TypeError,
            subprocess.TimeoutExpired) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

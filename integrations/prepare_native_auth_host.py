#!/usr/bin/env python3
"""Prepare the host requirements for Cerato native auth, WITHOUT cutover.

Two explicit modes:
 --check: read-only; reports file-pin, host context and dependency gates.
 --install: creates only the EMPTY private auth directory and one narrowly
   scoped web-service drop-in (no service restart, no account or database).
Does not pip/apt-install anything or change WireGuard, SSH, Nginx or routes.
The native authentication cannot activate without a separate signed cutover.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

WEB="cerato-network-web.service"
STORE=Path("/var/lib/cerato-network-auth")
CONF=Path("/etc/systemd/system/cerato-network-web.service.d/70-cerato-native-auth.conf")
USER="ceratonet"
ORIGIN="https://51.210.223.57"
EXPECTED={
    "/opt/cerato-network/backend/server.py":
      "0e5a7a41ae88fbbf7c1de49a9471a1ab521e174515f7a18b47b761542697c324",
    "/opt/cerato-network/web/app.js":
      "b4ae1e20cedb1c761c2bb8f8d2da04d612e16963d5edc2f1c7273203716f5232",
    "/opt/cerato-network/web/style.css":
      "431687f01d1c3adfbf0e150a459fe25ef2e1fffb7b4d05b734efd2d54dac75f5",
}
UPDATE="/usr/local/sbin/cerato-updatectl"
DROPIN=(
    "[Service]\n"
    "# Native accounts are not enabled until a signed, reviewed cutover.\n"
    "# Preserve ProtectSystem=strict and all other hardening.\n"
    "ReadWritePaths=/var/lib/cerato-network-auth\n"
    "Environment=CERATO_WEB_ORIGIN=https://51.210.223.57\n"
).encode()

class PrerequisiteError(ValueError):
    pass

def process(*args,timeout=18):
    try:
        return subprocess.run(args,check=False,capture_output=True,
                              text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PrerequisiteError("Commande de validation indisponible") from exc

def pinned_sources():
    for filename,sha in EXPECTED.items():
        p=Path(filename)
        if p.is_symlink() or not p.is_file() or p.stat().st_uid!=0:
            raise PrerequisiteError("Sources Web non reconnues : aucune action")
        if hashlib.sha256(p.read_bytes()).hexdigest()!=sha:
            raise PrerequisiteError("Empreinte Web différente de l'audit approuvé")
    if (s:=process(UPDATE,"status")).returncode:
        raise PrerequisiteError("Statut du moteur de mises à jour indisponible")
    try:
        data=json.loads(s.stdout)
    except (TypeError,ValueError) as exc:
        raise PrerequisiteError("Statut du moteur de mises à jour non JSON") from exc
    if data.get("installed_version")!="v0.1.2-beta.1":
        raise PrerequisiteError("Version du panneau incompatible avec le préflight")
    return True

def unit_context():
    if (p:=process("systemctl","is-active","--quiet",WEB)).returncode:
        raise PrerequisiteError("Service Web inactif")
    p=process("systemctl","show",WEB,
              "-p","User","-p","ProtectSystem","-p","ProtectHome",
              "-p","PrivateTmp","-p","NoNewPrivileges",
              "-p","ReadWritePaths","-p","Environment","--no-pager")
    if p.returncode:
        raise PrerequisiteError("Unité Web introuvable")
    props=dict(line.split("=",1) for line in p.stdout.splitlines() if "=" in line)
    expected={"User":USER,"ProtectSystem":"strict","ProtectHome":"yes",
              "PrivateTmp":"yes"}
    if any(props.get(k)!=v for k,v in expected.items()):
        raise PrerequisiteError("Confinement du service Web inattendu")
    return props

def ensure_trusted_directory(root:Path,*,owner_uid:int,owner_gid:int,
                             permissions:int):
    if root.is_symlink() or not root.is_dir():
        raise PrerequisiteError("Répertoire attendu absent ou symbolique")
    st=root.stat()
    if (st.st_uid!=owner_uid or st.st_gid!=owner_gid or
        stat.S_IMODE(st.st_mode)!=permissions):
        raise PrerequisiteError("Droits du répertoire non conformes")

def private_storage_state():
    user=pwd.getpwnam(USER)
    root=STORE.parent
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=0:
        raise PrerequisiteError("Parent du stockage privé non approuvé")
    if root.stat().st_mode & (stat.S_IWGRP|stat.S_IWOTH):
        raise PrerequisiteError("Parent du stockage privé accessible à un tiers")
    if STORE.is_symlink():
        raise PrerequisiteError("Stockage privé symbolique refusé")
    if STORE.exists():
        ensure_trusted_directory(STORE,owner_uid=user.pw_uid,
                                 owner_gid=user.pw_gid,permissions=0o700)
        if any(STORE.iterdir()):
            raise PrerequisiteError(
                "Stockage contient déjà des fichiers : ne pas écraser")
        return True
    return False

def dropin_state():
    base=CONF.parent.parent
    if not base.is_dir() or base.is_symlink() or base.stat().st_uid!=0:
        raise PrerequisiteError("Répertoire systemd non approuvé")
    if CONF.parent.exists():
        if CONF.parent.is_symlink() or not CONF.parent.is_dir():
            raise PrerequisiteError("Dossier de surcharge systemd invalide")
        if CONF.parent.stat().st_uid!=0 or (
            CONF.parent.stat().st_mode & (stat.S_IWGRP|stat.S_IWOTH)):
            raise PrerequisiteError("Dossier de surcharge non sûr")
    if CONF.is_symlink():
        raise PrerequisiteError("Surcharge systemd symbolique refusée")
    if not CONF.exists():
        return False
    if (not CONF.is_file() or CONF.stat().st_uid!=0 or
        stat.S_IMODE(CONF.stat().st_mode)!=0o644 or
        CONF.read_bytes()!=DROPIN):
        raise PrerequisiteError("Surcharge existante différente : refus")
    return True

def dependency_status():
    ready={}
    for distribution,module,minimum in (
        ("argon2-cffi","argon2",(25,1)),
        ("cryptography","cryptography",(44,0)),
    ):
        version=None
        try:
            version=importlib.metadata.version(distribution)
            numbers=tuple(int(x) for x in re.findall(r"\d+",version)[:2])
            ok=importlib.util.find_spec(module) is not None and numbers>=minimum
        except (importlib.metadata.PackageNotFoundError,ValueError,ImportError):
            ok=False
        ready[module]={"meets_pinned_requirements":ok}
    return ready

def preflight():
    if os.geteuid()!=0:
        raise PrerequisiteError("Exécution root nécessaire sur RISE-1")
    if ipaddress.ip_address(ORIGIN.removeprefix("https://")) != (
        ipaddress.ip_address("51.210.223.57")):
        raise PrerequisiteError("Origine de production inattendue")
    pinned_sources()
    props=unit_context()
    store=private_storage_state()
    dropin=dropin_state()
    if process("systemctl","is-active","--quiet",
               "cerato-network-update.service").returncode==0:
        raise PrerequisiteError("Mise à jour Web en cours : refus")
    return {"source_fingerprints_match":True,
            "installed_version":"v0.1.2-beta.1",
            "storage_directory_ready":store,
            "systemd_dropin_present":dropin,
            "service_uses_strict_filesystem":True,
            "service_restart_required_now":False,
            "origin_expected":ORIGIN,
            "dependency_status":dependency_status(),
            "network_modified":False,
            "live_auth_activated":False}

def install():
    state=preflight()
    user=pwd.getpwnam(USER)
    made_storage=False
    made_dropin=False
    reloaded=False
    try:
        if not state["storage_directory_ready"]:
            os.mkdir(STORE,0o700)
            made_storage=True
            os.chown(STORE,user.pw_uid,user.pw_gid)
            os.chmod(STORE,0o700)
            ensure_trusted_directory(STORE,owner_uid=user.pw_uid,
                                     owner_gid=user.pw_gid,permissions=0o700)
        if not state["systemd_dropin_present"]:
            CONF.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
            if CONF.parent.is_symlink() or CONF.parent.stat().st_uid!=0:
                raise PrerequisiteError("Dossier systemd devenu non sûr")
            fd=os.open(CONF,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
            made_dropin=True
            with os.fdopen(fd,"wb") as file:
                file.write(DROPIN)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(CONF,0o644)
        if (res:=process("systemctl","daemon-reload")).returncode:
            raise PrerequisiteError("Rechargement systemd refusé")
        reloaded=True
        props=unit_context()
        if (str(STORE) not in props.get("ReadWritePaths","").split() or
            "CERATO_WEB_ORIGIN="+ORIGIN not in props.get("Environment","")):
            raise PrerequisiteError("Autorisation privée ou origine absente de l'unité")
        state=preflight()
        return {"result":"prepared_inactive",
                **state,
                "db_initialized":False,
                "service_restarted":False}
    except BaseException:
        if made_dropin:
            CONF.unlink(missing_ok=True)
        if made_storage:
            try:
                STORE.rmdir()
            except OSError:
                pass
        if made_dropin or reloaded:
            process("systemctl","daemon-reload")
        raise

def main():
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--check",action="store_true")
    group.add_argument("--install",action="store_true")
    args=p.parse_args()
    try:
        result=preflight() if args.check else install()
    except (OSError,ValueError,PrerequisiteError) as exc:
        p.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))

if __name__=="__main__":
    main()

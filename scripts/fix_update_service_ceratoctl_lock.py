#!/usr/bin/env python3
"""Repair ONLY the systemd sandbox for the existing trusted Cerato Web updater.

ceratoctl status uses /etc/cerato-network/.ceratoctl.lock. ProtectSystem=strict
makes it read-only inside the update.service namespace. Add a writable exception
for that ONE existing, root-owned lockfile; never expose config.json or the
rest of /etc/cerato-network to the Web updater. No network changes.

--check: strict transient systemd sandbox preflight, no disk changes
--install: preflight then install drop-in, reload systemd (no service restart)
--install-and-apply: same, then launch the already verified/signed update
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

LOCK=Path("/etc/cerato-network/.ceratoctl.lock")
SERVICE="cerato-network-update.service"
WEB_SERVICE="cerato-network-web.service"
CONTROLLER=Path("/usr/local/sbin/ceratoctl")
UPDATER=Path("/usr/local/sbin/cerato-updatectl")
DROPIN=Path("/etc/systemd/system/cerato-network-update.service.d/60-ceratoctl-lock.conf")
DROPIN_TEXT=(
    "[Service]\n"
    "# Allow only the existing ceratoctl flock file to be written.\n"
    "# All network configs under /etc/cerato-network remain read-only.\n"
    "ReadWritePaths=/etc/cerato-network/.ceratoctl.lock\n"
)
SANDBOX_WRITABLE=(
    "/opt/cerato-network/backend "
    "/opt/cerato-network/web "
    "/var/lib/cerato-network-updates "
    "/etc/cerato-network/.ceratoctl.lock"
)
STATUS_CODE=r'''
import json,subprocess,sys
try:
    p=subprocess.run(["/usr/local/sbin/ceratoctl","status"],
                     text=True,capture_output=True,timeout=12)
    if p.returncode:
        raise RuntimeError("ceratoctl status non-zero")
    if not isinstance(json.loads(p.stdout),dict):
        raise RuntimeError("ceratoctl status JSON non objet")
    print("Statut Cerato valide sous sandbox systemd : True")
except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
    print("Statut Cerato valide sous sandbox systemd : False")
    sys.exit(4)
'''

class LockRepairError(RuntimeError):
    pass

def command(*args,timeout=30,check=True):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise LockRepairError("Commande système indisponible ou expirée : "+str(args[0])) from exc
    if check and p.returncode!=0:
        raise LockRepairError("Commande refusée : "+str(args[0])+" (code "+str(p.returncode)+")")
    return p

def unit_state():
    output=command("systemctl","show",SERVICE,"--no-pager",
                   "-p","ProtectSystem","-p","ProtectHome",
                   "-p","PrivateTmp","-p","NoNewPrivileges",
                   "-p","User","-p","ExecStart","-p","ReadWritePaths").stdout
    props=dict(line.split("=",1) for line in output.splitlines() if "=" in line)
    expected={"ProtectSystem":"strict","ProtectHome":"yes",
              "PrivateTmp":"yes","NoNewPrivileges":"yes","User":"root"}
    for key,value in expected.items():
        if props.get(key)!=value:
            raise LockRepairError("Sandbox systemd inattendue : "+key)
    if "/usr/local/sbin/cerato-updatectl apply" not in props.get("ExecStart",""):
        raise LockRepairError("ExecStart du service de mise à jour inattendu")
    return props

def prerequisites():
    if os.geteuid()!=0:
        raise LockRepairError("Exécution réservée à root sur Cerato Network OVH")
    if not LOCK.is_file() or LOCK.is_symlink():
        raise LockRepairError("Fichier de verrouillage absent ou symbolique : refus")
    mode=LOCK.stat()
    if mode.st_uid!=0 or mode.st_mode & (stat.S_IWGRP|stat.S_IWOTH):
        raise LockRepairError("Fichier de verrouillage accessible à un tiers")
    for path in (CONTROLLER,UPDATER):
        if not path.is_file() or path.is_symlink() or not os.access(path,os.X_OK):
            raise LockRepairError("Contrôleur absent ou exécutable invalide : "+str(path))
        if path.stat().st_uid!=0:
            raise LockRepairError("Contrôleur non détenu par root")
    unit_state()
    if command("systemctl","is-active","--quiet",SERVICE,check=False).returncode==0:
        raise LockRepairError("Installation en cours : refus")
    if command("systemctl","is-active","--quiet",WEB_SERVICE,check=False).returncode!=0:
        raise LockRepairError("Panneau Web inactif : refus")

def transient_test():
    label="cerato-lock-verify-"+str(os.getpid())
    args=("systemd-run","--quiet","--wait","--pipe","--collect",
          "--unit="+label,
          "-p","Type=oneshot",
          "-p","User=root",
          "-p","ProtectSystem=strict",
          "-p","ProtectHome=yes",
          "-p","PrivateTmp=yes",
          "-p","NoNewPrivileges=yes",
          "-p","ReadWritePaths="+SANDBOX_WRITABLE,
          "/usr/bin/python3","-c",STATUS_CODE)
    result=command(*args,timeout=40,check=False)
    if result.returncode!=0 or "Statut Cerato valide sous sandbox systemd : True" not in result.stdout:
        raise LockRepairError("Le contrôle en sandbox corrigée échoue : aucun changement appliqué")
    return True

def updater_status():
    try:
        data=json.loads(command(str(UPDATER),"status",timeout=30).stdout)
    except (ValueError,TypeError) as exc:
        raise LockRepairError("Statut updater invalide") from exc
    if not isinstance(data,dict):
        raise LockRepairError("Statut updater non objet")
    return data

def _trusted_dir(path:Path):
    info=path.stat()
    return info.st_uid==0 and not info.st_mode & (stat.S_IWGRP|stat.S_IWOTH)


def install_dropin():
    if DROPIN.is_symlink():
        raise LockRepairError("Drop-in systemd symbolique : refus")
    if DROPIN.exists():
        if not DROPIN.is_file() or DROPIN.read_text()!=DROPIN_TEXT:
            raise LockRepairError("Drop-in systemd existant différent : refus")
        return False
    directory=DROPIN.parent
    if directory.is_symlink():
        raise LockRepairError("Dossier drop-in symbolique : refus")
    directory.mkdir(mode=0o755,parents=True,exist_ok=True)
    if not _trusted_dir(directory):
        raise LockRepairError("Dossier drop-in non approuvé")
    # O_EXCL prevents overwriting a different file created after preflight.
    fd=os.open(DROPIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    try:
        with os.fdopen(fd,"w",encoding="utf8") as handle:
            handle.write(DROPIN_TEXT)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        DROPIN.unlink(missing_ok=True)
        raise
    try:
        command("systemctl","daemon-reload",timeout=30)
        actual=unit_state()["ReadWritePaths"].split()
        if str(LOCK) not in actual:
            raise LockRepairError("Exception d'écriture absente de la configuration active")
    except BaseException:
        DROPIN.unlink(missing_ok=True)
        command("systemctl","daemon-reload",timeout=30,check=False)
        raise
    return True

def apply_existing_signed_release():
    old=updater_status()
    if old.get("installed_version")=="v0.1.1-beta.1":
        return {"result":"already_installed","version":"v0.1.1-beta.1"}
    if (old.get("installed_version")!="v0.1.0-beta.1" or
        old.get("available_version")!="v0.1.1-beta.1" or
        old.get("installable") is not True or old.get("channel")!="beta"):
        raise LockRepairError("Version ou release disponible inattendue : aucune installation")
    command("systemctl","reset-failed",SERVICE,timeout=10)
    result=command("systemctl","start","--no-pager",SERVICE,timeout=140,check=False)
    updated=updater_status()
    if result.returncode or updated.get("installed_version")!="v0.1.1-beta.1":
        raise LockRepairError("Installation échouée ; consulter journalctl -u "+
                              SERVICE+" -n 35 --no-pager")
    if command("systemctl","is-active","--quiet",WEB_SERVICE,check=False).returncode:
        raise LockRepairError("Installation signalée réussie mais panneau Web inactif")
    return {"result":"installed","version":"v0.1.1-beta.1"}

def main():
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument("--check",action="store_true")
    group.add_argument("--install",action="store_true")
    group.add_argument("--install-and-apply",action="store_true")
    args=p.parse_args()
    try:
        prerequisites()
        transient_test()
        print("Préflight status ceratoctl sous ProtectSystem=strict : OK")
        if args.check:
            print("Aucune modification : test effectué dans un service temporaire")
            return
        created=install_dropin()
        print("Exception limitée au fichier .ceratoctl.lock :", "installée" if created else "déjà présente")
        print("Restrictions globales ProtectSystem=strict : conservées")
        if args.install_and_apply:
            print(json.dumps(apply_existing_signed_release(),sort_keys=True))
        else:
            print("Aucune installation Web déclenchée")
    except (LockRepairError,OSError,ValueError) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

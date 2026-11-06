#!/usr/bin/env python3
"""Install an idempotent peer-only route guard after a verified /32 cutover.

The production incident of 2026-11-06 was the disappearance of ip rule
1101 after the gateway/peer cutover had already been committed. The original
systemd restore unit was enabled at boot but not continuously monitored.

This installer NEVER touches OVH/gateway, addresses, nftables, WireGuard,
routes or the current SSH session. It writes two exact, root-owned systemd
units on the already-committed Dell only, enabling a periodic oneshot that
uses the existing idempotent, state-guarded "restore --role peer" command.
--check remains completely read-only. Fails closed on foreign units or
unhealthy/currently missing public route: repair via existing tool first.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

PUBLIC="54.37.165.151"
WG="wg-cerato"
RULE=1101
TABLE="51820"
CUTOVER=Path("/usr/local/sbin/cerato-routed-cutover")
STATE=Path("/var/lib/cerato-network/routed-54-37-165-151/state.json")
UNITS=Path("/etc/systemd/system")
SERVICE="cerato-routed-peer-guard.service"
TIMER="cerato-routed-peer-guard.timer"
ORIGINAL="cerato-routed-peer.service"
SERVICE_TEXT="""[Unit]
Description=Cerato Dell routed public IPv4 source-policy route reconciliation
Documentation=https://github.com/EXODEcola/Cerato-Network
After=network-online.target wg-quick@wg-cerato.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/cerato-routed-cutover restore --role peer
TimeoutStartSec=30
NoNewPrivileges=true
"""
TIMER_TEXT="""[Unit]
Description=Cerato Dell public /32 route self-healing guard

[Timer]
OnBootSec=1min
OnUnitInactiveSec=1min
AccuracySec=15s
Unit=cerato-routed-peer-guard.service

[Install]
WantedBy=timers.target
"""

class GuardError(ValueError):
    pass


def _cmd(*args):
    try:
        result=subprocess.run([str(v) for v in args],check=False,
                              capture_output=True,text=True,timeout=12)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise GuardError("Vérification système indisponible") from exc
    if result.returncode:
        raise GuardError("Contrôle échoué : "+str(args[:3]))
    return result.stdout.strip()


def _is_regular_owned(path,*,max_size):
    if path.is_symlink() or not path.is_file():
        raise GuardError("Fichier absent ou symbolique : "+str(path))
    info=path.stat()
    if (not 0<info.st_size<=max_size or info.st_uid!=0 or
            info.st_mode & (stat.S_IWGRP|stat.S_IWOTH)):
        raise GuardError("Fichier root non conforme : "+str(path))
    return path.read_bytes()


def _preflight():
    if os.geteuid()!=0:
        raise GuardError("Commande réservée à root")
    raw=_is_regular_owned(STATE,max_size=30_000)
    try:
        state=json.loads(raw)
    except ValueError as exc:
        raise GuardError("Etat de migration non JSON") from exc
    if (not isinstance(state,dict) or
            state.get("phase")!="committed" or state.get("role")!="peer"
            or state.get("version")!=1):
        raise GuardError("Migration Dell non confirmée : ne pas activer la surveillance")
    _is_regular_owned(CUTOVER,max_size=150_000)
    if _cmd("systemctl","is-enabled",ORIGINAL)!="enabled":
        raise GuardError("Service persistant du Dell non activé")
    if _cmd("systemctl","is-active",ORIGINAL)!="active":
        raise GuardError("Service persistant du Dell non actif")
    allowed=_cmd("ip","-4","rule","show")
    pattern=r"(?m)^\s*1101:\s+from 54\.37\.165\.151(?:/32)?\s+lookup 51820\b"
    if not re.search(pattern,allowed):
        raise GuardError("Route source 1101 absente : réparer avant installation")
    table=_cmd("ip","-4","route","show","table",TABLE)
    if "default dev "+WG not in table:
        raise GuardError("Table 51820 ne possède pas la route WG attendue")
    addr=_cmd("ip","-4","addr","show","dev",WG)
    if PUBLIC+"/32" not in addr:
        raise GuardError("IPv4 publique Dell absente")
    observed=json.loads(_cmd("ip","-j","-4","route","get","1.1.1.1","from",PUBLIC))
    if not isinstance(observed,list) or len(observed)!=1 or observed[0].get("dev")!=WG:
        raise GuardError("Route retour publique incorrecte")
    return {"role":"peer","public_ipv4":PUBLIC,"route_source_ok":True,
            "original_service":"active","network_modified":False}


def _verify_absent_or_exact(path,content):
    if path.is_symlink():
        raise GuardError("Unité systemd symbolique interdite")
    if not path.exists():
        return False
    if not path.is_file() or path.read_bytes()!=content.encode("utf8"):
        raise GuardError("Unité systemd étrangère ou ancienne : intervention refusée")
    return True


def _write_exclusive(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    try:
        with os.fdopen(fd,"w",encoding="utf8") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def check():
    report=_preflight()
    report["service_unit_installed"]=_verify_absent_or_exact(UNITS/SERVICE,SERVICE_TEXT)
    report["timer_unit_installed"]=_verify_absent_or_exact(UNITS/TIMER,TIMER_TEXT)
    return report


def install():
    report=check()
    if UNITS.is_symlink() or not UNITS.is_dir():
        raise GuardError("Répertoire systemd non fiable")
    created=[]
    try:
        for name,content in ((SERVICE,SERVICE_TEXT),(TIMER,TIMER_TEXT)):
            path=UNITS/name
            if not _verify_absent_or_exact(path,content):
                _write_exclusive(path,content)
                created.append(path)
        _cmd("systemctl","daemon-reload")
        _cmd("systemctl","enable","--now",TIMER)
        if _cmd("systemctl","is-active",TIMER)!="active":
            raise GuardError("Timer guard non actif")
    except BaseException:
        # Remove only files that this command created, not foreign units.
        if created:
            subprocess.run(["systemctl","disable","--now",TIMER],
                           capture_output=True,timeout=12,check=False)
            for path in created:
                path.unlink(missing_ok=True)
            subprocess.run(["systemctl","daemon-reload"],
                           capture_output=True,timeout=12,check=False)
        raise
    report["timer_active"]=True
    report["service_unit_installed"]=True
    report["timer_unit_installed"]=True
    report["network_modified"]=False
    report["recovery_delay"]="environ 1-2 minutes après une perte de route"
    return report


def main():
    parser=argparse.ArgumentParser(description="Cerato Dell public IP route guard")
    parser.add_argument("action",choices=["check","install"],nargs="?",default="check")
    args=parser.parse_args()
    try:
        result=check() if args.action=="check" else install()
    except (GuardError,OSError,ValueError,KeyError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()

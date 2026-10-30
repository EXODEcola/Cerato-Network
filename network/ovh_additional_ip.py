#!/usr/bin/env python3
"""Add one OVH Additional IPv4 persistently, without touching live routes/WG.

Linux/Ubuntu native model: a dedicated systemd oneshot re-applies ONLY
Cerato-managed /32 addresses after boot, rather than rewriting the user's
existing Netplan/cloud-init YAML. The live command uses ip address add, never
netplan apply, ip route flush, systemctl restart networking, or WG changes.

Provider ownership cannot be proven from the Linux network alone. This
command requires a privileged authenticated admin action; a future OVH API
connector must verify attachment to the right dedicated-server service.
"""
from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

CONFIG=Path(os.environ.get("CERATO_CONFIG","/etc/cerato-network/config.json"))
STATE=Path(os.environ.get("CERATO_ADDITIONAL_IP_STATE",
                           "/etc/cerato-network/additional-ip-managed.json"))
LOCK=Path(os.environ.get("CERATO_ADDITIONAL_IP_LOCK",
                          "/etc/cerato-network/.additional-ip.lock"))
RESERVED_PORTS={22,23,25,53,110,143,445,3306,5432,6379,8006,8088,8787,8788,51820}
IFACE=re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class IPError(Exception):
    pass


def run(*argv):
    try:
        result=subprocess.run(argv,check=False,capture_output=True,
                              text=True,timeout=8)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise IPError("Commande système indisponible") from exc
    if result.returncode:
        raise IPError("Commande système refusée: "+str(argv[:3]))
    return result.stdout


def validate_public(value):
    try:
        addr=ipaddress.ip_address(value)
    except (ValueError,TypeError):
        raise IPError("Adresse IPv4 invalide")
    if addr.version!=4 or not addr.is_global:
        raise IPError("Adresse IPv4 publique obligatoire")
    return str(addr)


def read_config():
    data=json.loads(CONFIG.read_text(encoding="utf8"))
    for key in ("wan_if","wg_if","peers","pool","mappings"):
        if key not in data:
            raise IPError("Configuration Cerato incomplète")
    if not IFACE.fullmatch(str(data["wan_if"])):
        raise IPError("Interface WAN invalide")
    return data


def effective_wan(config):
    routes=json.loads(run("ip","-j","-4","route","get","1.1.1.1"))
    if len(routes)!=1 or routes[0].get("dev")!=config["wan_if"]:
        raise IPError("WAN détectée différente de la configuration; opération refusée")
    src=routes[0].get("prefsrc") or routes[0].get("src")
    if not src:
        raise IPError("Impossible de détecter l'IPv4 principale")
    return config["wan_if"],src


def listed(wan):
    address=json.loads(run("ip","-j","-4","addr","show","dev",wan))
    return {item.get("local") for iface in address
            for item in iface.get("addr_info",[])
            if item.get("family")=="inet"}


def state_read():
    if STATE.is_symlink():
        raise IPError("État Cerato symbolique refusé")
    if not STATE.exists():
        return {"schema":1,"local_ipv4":[]}
    record=json.loads(STATE.read_text(encoding="utf8"))
    if record.get("schema")!=1 or not isinstance(record.get("local_ipv4"),list):
        raise IPError("Fichier d'état Cerato invalide")
    if len(record["local_ipv4"])>256:
        raise IPError("Trop d'adresses gérées")
    for entry in record["local_ipv4"]:
        validate_public(entry["ip"])
        if not IFACE.fullmatch(entry["wan"]):
            raise IPError("Nom WAN invalide dans la configuration")
    return record


def save(record):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    if STATE.parent.is_symlink():
        raise IPError("Répertoire de configuration symbolique refusé")
    raw=(json.dumps(record,indent=2,sort_keys=True)+"\n").encode("utf8")
    fd,path=tempfile.mkstemp(prefix=".additional-ip-",dir=STATE.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(path,STATE)
    finally:
        Path(path).unlink(missing_ok=True)


def preflight(ip):
    cfg=read_config()
    wan,primary=effective_wan(cfg)
    address=validate_public(ip)
    if address==primary:
        raise IPError("IPv4 principale réservée à SSH et WireGuard")
    if address in {str(p.get("ip")) for p in cfg["peers"].values()}:
        raise IPError("Collision avec le réseau WireGuard")
    return cfg,wan,address,primary


def status():
    cfg=read_config()
    wan,primary=effective_wan(cfg)
    active=listed(wan)
    state=state_read()
    return {"wan":wan,"primary_ipv4":primary,
            "managed":[{"ip":x["ip"],"present":x["ip"] in active,"mode":"local-nat"}
                       for x in state["local_ipv4"]],
            "pool":cfg["pool"],"mappings":len(cfg["mappings"])}


def preview(ip,mode="local-nat"):
    if mode not in ("local-nat","routed-wg"):
        raise IPError("Mode inconnu")
    cfg,wan,address,primary=preflight(ip)
    peer_list=list(cfg["peers"])
    return {"ip":address,"wan":wan,"primary_ipv4":primary,
            "already_on_wan":address in listed(wan),
            "already_in_pool":address in cfg["pool"],
            "mode":mode,"peers":peer_list,
            "supported":mode=="local-nat",
            "reason":("Configuration locale persistante sans restart, avec NAT existant"
                      if mode=="local-nat" else
                      "Nécessite un agent Windows sur la machine, validation aller/retour et rollback; pas encore activé")}


def import_local(ip):
    cfg,wan,address,primary=preflight(ip)
    present=address in listed(wan)
    state=state_read()
    existing={item["ip"] for item in state["local_ipv4"]}
    if address in existing:
        return {"ip":address,"wan":wan,"already_managed":True,
                "present":present}
    # Address assignment by OVH must be checked through OVH API in a future
    # connector. Never claim this is automatic proof of provider ownership.
    if len(existing)>=256:
        raise IPError("Limite d'adresses atteinte")
    if not present:
        run("ip","-4","address","add",address+"/32","dev",wan)
    try:
        if address not in listed(wan):
            raise IPError("Additional IPv4 non présente après attribution")
        state["local_ipv4"].append({"ip":address,"wan":wan})
        save(state)
    except Exception:
        if not present:
            try:run("ip","-4","address","del",address+"/32","dev",wan)
            except IPError:pass
        raise
    return {"ip":address,"wan":wan,"already_managed":False,
            "present":True,"persisted":True,
            "note":"Réinstallation au démarrage par le service Cerato; OVH ownership vérifiable séparément"}


def restore():
    state=state_read()
    cfg=read_config()
    wan,_=effective_wan(cfg)
    for item in state["local_ipv4"]:
        if item["wan"] != wan:
            raise IPError("WAN changé : restauration arrêtée pour éviter une erreur")
        ip=validate_public(item["ip"])
        if ip not in listed(wan):
            run("ip","-4","address","add",ip+"/32","dev",wan)
    return {"restored":len(state["local_ipv4"])}


def remove_local(ip):
    cfg,wan,address,primary=preflight(ip)
    if address in cfg["pool"]:
        raise IPError("Retirer d'abord l'IP du pool et toutes ses publications")
    if any(m["public_ip"]==address for m in cfg["mappings"]):
        raise IPError("L'IP possède des publications NAT")
    state=state_read()
    if not any(x["ip"]==address for x in state["local_ipv4"]):
        raise IPError("Cette IP n'est pas gérée par Cerato")
    state["local_ipv4"]=[x for x in state["local_ipv4"] if x["ip"]!=address]
    # Persist the removal first, then remove only the managed /32 alias,
    # never modify any gateway route, peer or the primary IP.
    old=state_read()
    save(state)
    try:
        if address in listed(wan):
            run("ip","-4","address","del",address+"/32","dev",wan)
    except Exception:
        save(old)
        raise
    return {"removed":address}


def main():
    parser=argparse.ArgumentParser(description="Cerato Network: OVH Additional IPv4 local address")
    sub=parser.add_subparsers(dest="action",required=True)
    sub.add_parser("status")
    sub.add_parser("restore")
    p=sub.add_parser("preview");p.add_argument("ip");p.add_argument("--mode",default="local-nat")
    a=sub.add_parser("import-local");a.add_argument("ip")
    d=sub.add_parser("remove-local");d.add_argument("ip")
    args=parser.parse_args()
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    if LOCK.is_symlink():
        parser.error("Verrou symbolique refusé")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        if args.action=="status":result=status()
        elif args.action=="preview":result=preview(args.ip,args.mode)
        elif args.action=="restore":result=restore()
        elif args.action=="import-local":result=import_local(args.ip)
        else:result=remove_local(args.ip)
    except (IPError,OSError,ValueError,KeyError,TypeError) as exc:
        parser.error(str(exc))
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
    print(json.dumps(result,ensure_ascii=False))

if __name__=="__main__":
    main()

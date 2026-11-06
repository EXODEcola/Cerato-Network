#!/usr/bin/env python3
"""Read-only audit of Cerato gateway's persistent IPv4 /32 cutover conflicts.

Does not change addresses, WireGuard, firewall, systemd, SSH, or configuration.
Does not emit raw config, secret data, peer keys, or nftables rules.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import re


CONFIG=Path("/etc/cerato-network/config.json")
MANAGED=Path("/etc/cerato-network/additional-ip-managed.json")
NAME=re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def public_ip(value):
    try:
        addr=ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Adresse invalide") from exc
    if addr.version!=4 or not addr.is_global:
        raise argparse.ArgumentTypeError("IPv4 publique requise")
    return str(addr)


def tunnel_ip(value):
    try:
        addr=ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Adresse invalide") from exc
    if addr.version!=4 or not addr.is_private:
        raise argparse.ArgumentTypeError("IPv4 VPN privée requise")
    return str(addr)


def shell_read(args):
    try:
        process=subprocess.run(args,capture_output=True,text=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None
    return process.stdout if process.returncode==0 else None


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1_000_000:
        return None
    try:
        doc=json.loads(path.read_text(encoding="utf-8"))
    except (ValueError,OSError,UnicodeError):
        return None
    return doc if isinstance(doc,dict) else None


def yes_no_unknown(v):
    return "unknown" if v is None else ("yes" if v else "no")


def has_local_address(read,wan,ip):
    raw=read(["ip","-j","-4","address","show","dev",wan])
    if raw is None:
        return None
    try:
        return any(e.get("local")==ip and e.get("family")=="inet"
                   for device in json.loads(raw)
                   for e in device.get("addr_info",[]))
    except (ValueError,TypeError,AttributeError):
        return None


def peer_public_allowed(read,wg,peer,public):
    raw=read(["wg","show",wg,"allowed-ips"])
    if raw is None:
        return None
    for line in raw.splitlines():
        parts=line.split()
        if len(parts)<2:
            continue
        networks=[]
        for token in parts[1:]:
            try:
                networks.append(ipaddress.ip_network(token,strict=False))
            except ValueError:
                continue
        if any(ipaddress.ip_address(peer) in net for net in networks):
            return any(net == ipaddress.ip_network(public+"/32") for net in networks)
    return False


def service_state(read,name):
    v=read(["systemctl","is-enabled",name])
    return v.strip() if v is not None else "unknown"


def audit(public,peer,wan,wg,*,read=shell_read,config=CONFIG,managed=MANAGED):
    for value in (wan,wg):
        if not NAME.fullmatch(value):
            raise ValueError("Nom d'interface invalide")
    if wan==wg:
        raise ValueError("Interfaces identiques")
    raw=read_json(config)
    state=read_json(managed)
    mappings=None
    pool=None
    if raw is not None:
        pool=public in raw.get("pool",[])
        known=raw.get("mappings")
        if isinstance(known,list):
            mappings=sum(isinstance(m,dict) and m.get("public_ip")==public
                         for m in known)
    managed_ip=None
    if state is not None and isinstance(state.get("local_ipv4"),list):
        managed_ip=any(isinstance(e,dict) and e.get("ip")==public and e.get("wan")==wan
                       for e in state["local_ipv4"])

    alias=has_local_address(read,wan,public)
    allowed=peer_public_allowed(read,wg,peer,public)
    restore=service_state(read,"cerato-network-additional-ip.service")
    rules=service_state(read,"cerato-network-rules.service")
    flags={
        "public_ip_still_local_on_wan":yes_no_unknown(alias),
        "public_ip_managed_for_recreate_on_boot":yes_no_unknown(managed_ip),
        "public_ip_present_in_cerato_pool":yes_no_unknown(pool),
        "per_port_nat_mappings_for_public_ip":mappings,
        "wg_peer_allows_public_32":yes_no_unknown(allowed),
        "additional_ip_restore_service":restore,
        "cerato_rules_service":rules,
    }
    blockers=[]
    if alias is not False:
        blockers.append("live_wan_alias_needs_coordinated_migration")
    if managed_ip is not False:
        blockers.append("persistent_alias_restore_needs_migration")
    if mappings is None or mappings!=0:
        blockers.append("nat_mappings_require_atomic_conversion")
    if allowed is not True:
        blockers.append("wg_peer_public_32_not_prepared")
    if raw is None or pool is not True:
        blockers.append("cerato_config_or_pool_needs_review")
    if rules!="disabled" and rules!="masked":
        # The nftables table may be recreated by Cerato after a service action.
        blockers.append("rules_regenerator_must_support_routed_mode")
    return {
        "format":"cerato-routed-cutover-dependency-audit-v1",
        "role":"gateway",
        "public_ip":public,"vpn_peer_ip":peer,
        "wan":wan,"wg":wg,
        "findings":flags,
        "blockers":sorted(blockers),
        "can_activate":False,
        "modified":False,
        "security_note":"Le rapport ne donne aucune clé WireGuard ni fichier de configuration brut.",
    }


def main():
    parser=argparse.ArgumentParser(description="Audit read-only Cerato RISE-1 Additional IPv4")
    parser.add_argument("--public-ip",required=True,type=public_ip)
    parser.add_argument("--peer-ip",required=True,type=tunnel_ip)
    parser.add_argument("--wan",required=True)
    parser.add_argument("--wg",default="wg-cerato")
    options=parser.parse_args()
    print(json.dumps(audit(options.public_ip,options.peer_ip,options.wan,options.wg),
                     indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

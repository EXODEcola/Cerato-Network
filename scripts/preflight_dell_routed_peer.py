#!/usr/bin/env python3
"""Dell R530 public IPv4 /32 readiness audit (READ ONLY, fails closed).

No edits, no sudo escalation, no private keys, no WG config dumps, no nftables
commands and no changes to routing, SSH, firewall or systemd.
The firewall state cannot be certified by this script; even healthy observations
do not authorize activation or removal of the gateway's WAN IPv4 alias.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import re
import subprocess

IFACE=re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")
TABLE=re.compile(r"^[0-9]{1,10}$")


class AuditError(ValueError):
    pass


def validate(ip,*,global_only=False,private_only=False):
    try:
        addr=ipaddress.ip_address(ip)
    except (TypeError,ValueError) as exc:
        raise AuditError("IPv4 invalide") from exc
    if addr.version!=4 or (global_only and not addr.is_global) or (
            private_only and not addr.is_private):
        raise AuditError("Plage IPv4 incorrecte")
    return str(addr)


def command(argv):
    allowed={"ip","sysctl","ss","ufw","systemctl","/usr/sbin/sshd"}
    if not argv or argv[0] not in allowed:
        raise AuditError("Commande de diagnostic non autorisée")
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=7,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AuditError("Diagnostic système indisponible") from exc
    if p.returncode:
        raise AuditError("Diagnostic indisponible")
    return p.stdout


def read(readfn,args,parser):
    try:
        return parser(readfn(args))
    except (AuditError,ValueError,KeyError,TypeError,IndexError,AttributeError,
            json.JSONDecodeError):
        return None


def addresses(raw):
    return {x.get("local") for item in json.loads(raw)
            for x in item.get("addr_info",[]) if x.get("family")=="inet"}


def ssh(raw):
    fields={}
    for line in raw.splitlines():
        name,sep,val=line.partition(" ")
        if sep and name in ("passwordauthentication","kbdinteractiveauthentication",
                            "pubkeyauthentication","permitrootlogin"):
            fields[name]=val.strip().lower()
    keys={"passwordauthentication":"no","kbdinteractiveauthentication":"no",
          "pubkeyauthentication":"yes","permitrootlogin":"no"}
    return all(fields.get(k)==v for k,v in keys.items()) if len(fields)==4 else None


def route_device(raw):
    rows=json.loads(raw)
    if not isinstance(rows,list) or not rows:
        raise AuditError("Route introuvable")
    return rows[0].get("dev")


def from_rule_table(raw,source):
    found=[]
    for line in raw.splitlines():
        match=re.search(r"^\s*(\d+):\s+from\s+"+
                        re.escape(source)+r"(?:/32)?\s+lookup\s+(\w+)\b",line)
        if match:
            found.append((int(match.group(1)),match.group(2)))
    return found


def table_has_default_via_wg(raw,tunnel):
    return bool(re.search(r"(?m)^default\s+dev\s+"+re.escape(tunnel)+r"(?:\s|$)",raw))


def listen_ports(raw):
    tcp=set()
    for line in raw.splitlines():
        parts=line.split()
        if len(parts)<4:
            continue
        local=parts[3]
        match=re.search(r":(\d{1,5})$",local)
        if not match:
            continue
        port=int(match.group(1))
        if 1<=port<=65535:
            tcp.add(port)
    return sorted(tcp)


def ufw_status(raw):
    match=re.search(r"(?im)^Status:\s*(active|inactive)\s*$",raw)
    return match.group(1).lower() if match else None


def check(readfn,*,public_ip,vpn_ip,tunnel,table,priority):
    pub=validate(public_ip,global_only=True)
    vpn=validate(vpn_ip,private_only=True)
    if not IFACE.fullmatch(tunnel):
        raise AuditError("Tunnel non conforme")
    if type(table) is not int or not 256<=table<=0xffffffff:
        raise AuditError("Table de routage interdite")
    if type(priority) is not int or not 1000<=priority<=4999:
        raise AuditError("Priorité de routage invalide")

    wgaddrs=read(readfn,["ip","-j","-4","address","show","dev",tunnel],addresses)
    rules=read(readfn,["ip","-4","rule","show"],lambda x:x)
    routes=read(readfn,["ip","-4","route","show","table",str(table)],lambda x:x)
    source_dev=read(readfn,["ip","-j","-4","route","get","1.1.1.1",
                            "from",vpn],route_device)
    sys_all=read(readfn,["sysctl","-n","net.ipv4.conf.all.rp_filter"],
                 lambda x:int(x.strip()))
    sys_wg=read(readfn,["sysctl","-n",f"net.ipv4.conf.{tunnel}.rp_filter"],
                lambda x:int(x.strip()))
    ssh_key=read(readfn,["/usr/sbin/sshd","-T"],ssh)
    ufw_state=read(readfn,["ufw","status"],ufw_status)
    ports=read(readfn,["ss","-H","-ltn"],listen_ports)
    tailscale=read(readfn,["ip","link","show","dev","tailscale0"],lambda _ :True)
    peer_rule=from_rule_table(rules,vpn) if rules is not None else None
    public_rule=from_rule_table(rules,pub) if rules is not None else None
    occupied=(any(int(match.group(1))==priority
                  for line in rules.splitlines()
                  if (match:=re.match(r"^\s*(\d+):",line)))
              if rules is not None else None)

    tests={
        "wg_interface_has_vpn_ip":None if wgaddrs is None else vpn in wgaddrs,
        "public_ip_not_yet_on_wg":None if wgaddrs is None else pub not in wgaddrs,
        "vpn_source_returns_via_wg":None if source_dev is None else source_dev==tunnel,
        "policy_table_default_uses_wg":None if routes is None else
                                     table_has_default_via_wg(routes,tunnel),
        "vpn_source_policy_exists":None if peer_rule is None else
                                   any(name==str(table) for _,name in peer_rule),
        "target_priority_available":None if occupied is None else not occupied,
        "public_source_policy_not_yet_set":None if public_rule is None else not bool(public_rule),
        "rp_filter_non_strict":None if sys_all is None or sys_wg is None else
                                  max(sys_all,sys_wg)!=1,
        "ssh_global_publickey_only":ssh_key,
        "sshd_listens_on_tcp22":None if ports is None else 22 in ports,
        "tailscale_interface_present":tailscale,
    }
    flags={k:("pass" if v is True else "block" if v is False else "unknown")
           for k,v in tests.items()}
    issues=sorted(k for k,val in flags.items() if val!="pass")
    return {
        "format":"cerato-dell-routed-peer-readiness-v1",
        "machine":"dell-peer",
        "public_ip":pub,"vpn_ip":vpn,"tunnel":tunnel,
        "routing_table":table,"reserved_rule_priority":priority,
        "checks":flags,
        "listening_tcp_ports":ports,
        "ufw_state":ufw_state or "unknown",
        "host_public_firewall_reviewed":False,
        "gateway_cutover_authorized":False,
        "rollback_armed":False,
        "tailscale_recovery_independently_verified":False,
        "remaining_observed_issues":issues,
        "ready_to_activate":False,
        "modified":False,
        "note":"Audit en lecture seule. La présence d'UFW ou de Tailscale ne prouve ni le filtrage de l'IPv4 publique ni une récupération indépendante.",
    }


def main():
    p=argparse.ArgumentParser(description="Cerato Dell /32 read-only readiness audit")
    p.add_argument("--public-ip",required=True)
    p.add_argument("--vpn-ip",required=True)
    p.add_argument("--tunnel",default="wg-cerato")
    p.add_argument("--table",type=int,default=51820)
    p.add_argument("--priority",type=int,default=1101)
    a=p.parse_args()
    try:
        report=check(command,public_ip=a.public_ip,vpn_ip=a.vpn_ip,
                     tunnel=a.tunnel,table=a.table,priority=a.priority)
    except AuditError as exc:
        p.error(str(exc))
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()

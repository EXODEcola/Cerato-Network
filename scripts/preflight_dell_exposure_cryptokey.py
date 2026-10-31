#!/usr/bin/env python3
"""Read-only Dell R530 exposure and WireGuard cryptokey routing audit.

Only prints anonymized listener binding classes, ports and boolean observations.
Never outputs peer keys, identities, raw nftables rules or LAN addresses.
No changes to network, services, firewall, SSH, WireGuard or systemd.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess


class AuditError(ValueError):
    pass


def ipv4(value, public=False, private=False):
    try:
        addr=ipaddress.ip_address(value)
    except (ValueError,TypeError) as exc:
        raise AuditError("IPv4 invalide") from exc
    if addr.version != 4 or (public and not addr.is_global) or (private and not addr.is_private):
        raise AuditError("Adresse non conforme")
    return str(addr)


def shell_read(args):
    cmd=args[0] if args else ""
    if cmd not in ("wg", "ss", "nft", "ip"):
        raise AuditError("Commande non approuvée")
    try:
        r=subprocess.run(args,text=True,capture_output=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode==0 else None


def gateway_cryptokey(raw, vpn_gateway_ip):
    """Find unique WG peer whose AllowedIPs includes the VPN gateway IP.

    Never retains or emits the peer's public key in returned result.
    A route-table default alone is not enough: a WG peer must also
    authorize arbitrary public destination IPs for full-tunnel egress.
    """
    if raw is None:
        return {"gateway_peer_unique":"unknown","internet_allowed_ips":"unknown"}
    gateway=ipaddress.IPv4Address(vpn_gateway_ip)
    found=[]
    try:
        for line in raw.splitlines():
            parts=line.split()
            if len(parts)<2:
                continue
            nets=[]
            for value in parts[1:]:
                nets.append(ipaddress.ip_network(value.strip(','),strict=False))
            if any(gateway in network for network in nets):
                found.append(nets)
    except ValueError:
        return {"gateway_peer_unique":"unknown","internet_allowed_ips":"unknown"}
    if len(found)!=1:
        return {"gateway_peer_unique":"block","internet_allowed_ips":"unknown"}
    return {
        "gateway_peer_unique":"pass",
        # Must support all IPv4 destinations; sample coverage is insufficient.
        "internet_allowed_ips":"pass" if any(
            net==ipaddress.IPv4Network("0.0.0.0/0") for net in found[0]
        ) else "block",
    }


def classify_host(host):
    if host in ("*","0.0.0.0"):
        return "all_ipv4"
    if host in ("::","[::]"):
        return "all_ipv6"
    host=host.strip("[]").split("%",1)[0]
    try:
        address=ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.version==6 and address.is_link_local:
        return "ipv6_linklocal"
    if address.is_global:
        return "global_ipv"+str(address.version)
    return "nonpublic_ipv"+str(address.version)


def listeners(raw):
    if raw is None:
        return None
    found=set()
    for line in raw.splitlines():
        items=line.split()
        if len(items)<5:
            continue
        local=items[3]
        # The host may be 0.0.0.0, IPv4, [IPv6], wildcard, or scoped IPv6.
        match=re.fullmatch(r"(.+):(\d{1,5})",local)
        if not match:
            continue
        host,number=match.groups()
        port=int(number)
        if not 1<=port<=65535:
            continue
        found.add((port,classify_host(host)))
    return [{"port":port,"binding":bind} for port,bind in sorted(found)]


def nft_input_hooks(raw):
    if raw is None:
        return {"readable":False,"input_hooks":None,"ip6_input_hooks":None}
    try:
        doc=json.loads(raw)
        entries=doc["nftables"]
        if not isinstance(entries,list):
            raise ValueError("Invalid nftables")
    except (KeyError,TypeError,ValueError,AttributeError):
        return {"readable":False,"input_hooks":None,"ip6_input_hooks":None}
    inputs=0
    ipv6=0
    for item in entries:
        if not isinstance(item,dict) or not isinstance(item.get("chain"),dict):
            continue
        chain=item["chain"]
        if chain.get("hook")!="input":
            continue
        inputs+=1
        if chain.get("family") in ("ip6","inet"):
            ipv6+=1
    return {"readable":True,"input_hooks":inputs,"ip6_input_hooks":ipv6}


def check(readfn,*,public_ip,vpn_gateway_ip,tunnel):
    pub=ipv4(public_ip,public=True)
    gateway=ipv4(vpn_gateway_ip,private=True)
    if not isinstance(tunnel,str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,32}",tunnel):
        raise AuditError("Interface tunnel invalide")
    outputs={}
    for name,args in {
        "wg_allowed":["wg","show",tunnel,"allowed-ips"],
        "tcp":["ss","-H","-ltn"],
        "udp":["ss","-H","-lun"],
        "nft":["nft","-j","list","ruleset"],
        "addresses":["ip","-j","-4","address","show"],
        "ipv6":["ip","-j","-6","address","show"],
    }.items():
        outputs[name]=readfn(args)
    cryptokey=gateway_cryptokey(outputs["wg_allowed"],gateway)
    try:
        address_data=json.loads(outputs["addresses"]) if outputs["addresses"] is not None else None
        if address_data is not None and not isinstance(address_data,list):
            address_data=None
    except (ValueError,TypeError):
        address_data=None
    public_assigned=None
    if address_data is not None:
        public_assigned=any(
            info.get("local")==pub for row in address_data
            if isinstance(row,dict) for info in row.get("addr_info",[])
            if isinstance(info,dict))
    try:
        v6_data=json.loads(outputs["ipv6"]) if outputs["ipv6"] is not None else None
        if v6_data is not None and not isinstance(v6_data,list):
            v6_data=None
    except (ValueError,TypeError):
        v6_data=None
    ipv6_global=None
    if v6_data is not None:
        try:
            ipv6_global=any(
                isinstance(info,dict) and isinstance(info.get("local"),str) and
                ipaddress.ip_address(info["local"]).version==6 and
                ipaddress.ip_address(info["local"]).is_global
                for row in v6_data if isinstance(row,dict)
                for info in row.get("addr_info",[]))
        except ValueError:
            ipv6_global=None
    tcp=listeners(outputs["tcp"])
    udp=listeners(outputs["udp"])
    nft=nft_input_hooks(outputs["nft"])
    checks={
        "unique_gateway_wireguard_peer":cryptokey["gateway_peer_unique"],
        "wireguard_peer_supports_full_ipv4_egress":cryptokey["internet_allowed_ips"],
        "public_ip_not_assigned_to_any_dell_interface":(
            "unknown" if public_assigned is None else "block" if public_assigned else "pass"),
        "tcp_listeners_readable":"pass" if tcp is not None else "unknown",
        "udp_listeners_readable":"pass" if udp is not None else "unknown",
        "nftables_ruleset_inspected":"pass" if nft["readable"] else "unknown",
    }
    return {
        "format":"cerato-dell-exposure-cryptokey-audit-v1",
        "machine":"dell-peer",
        "public_ip":pub,
        "vpn_gateway_ip":gateway,
        "checks":checks,
        "tcp_listeners":tcp,
        "udp_listeners":udp,
        "nft_input_hook_count":nft["input_hooks"],
        "ipv6_input_hook_count":nft["ip6_input_hooks"],
        "global_ipv6_present":ipv6_global,
        "public_ipv4_firewall_confirmed":False,
        "tailscale_independent_recovery_verified":False,
        "ready_to_activate":False,
        "network_modified":False,
        "note":"Ports à écoute globale ne sont pas nécessairement accessibles depuis Internet. Les chaînes nft ne prouvent pas une protection ni l'absence d'autres filtres.",
    }


def main():
    parser=argparse.ArgumentParser(description="Audit Dell exposure+WG en lecture seule")
    parser.add_argument("--public-ip",required=True)
    parser.add_argument("--gateway-vpn-ip",default="10.77.0.1")
    parser.add_argument("--tunnel",default="wg-cerato")
    args=parser.parse_args()
    try:
        result=check(shell_read,public_ip=args.public_ip,
                     vpn_gateway_ip=args.gateway_vpn_ip,tunnel=args.tunnel)
    except AuditError as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()

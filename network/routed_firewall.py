"""Pure nftables routing rules for an OVH Additional IPv4 delivered via WireGuard.

The caller integrates generated statements BEFORE existing broad DROP
statements in its authoritative nftables table. This module MUST NOT execute
nft, flush a table, alter WireGuard, modify files or touch routes.
"""
from __future__ import annotations
import ipaddress
import re

IFACE=re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class FirewallPreviewError(ValueError):
    pass


def ipv4(value,*,global_only=False,private_only=False):
    try:
        addr=ipaddress.ip_address(value)
    except (ValueError,TypeError) as exc:
        raise FirewallPreviewError("Invalid IPv4") from exc
    if addr.version!=4 or (global_only and not addr.is_global) or (
            private_only and not addr.is_private):
        raise FirewallPreviewError("Invalid IPv4 range")
    return str(addr)


def iface(value):
    if not isinstance(value,str) or not IFACE.fullmatch(value):
        raise FirewallPreviewError("Invalid interface")
    return value


def routed_rules(*,wan,wg,management_ip,assignments,peers,legacy_nat_mappings):
    """Return only safe rule statements, not a script to execute.

    assignments: list [{"ip": "<public IPv4>", "peer": "peer-name"}]
    peers: name -> {"ip": "<private VPN IPv4>"}
    Caller must atomically migrate legacy NAT and configure host firewall
    and verified cryptokey routing before enabling any of these lines.
    """
    wan=iface(wan); wg=iface(wg)
    if wan==wg:
        raise FirewallPreviewError("Same WAN/WG interface")
    admin=ipv4(management_ip,global_only=True)
    if not isinstance(assignments,list) or not isinstance(peers,dict):
        raise FirewallPreviewError("Invalid assignments/peers")
    if not isinstance(legacy_nat_mappings,list):
        raise FirewallPreviewError("NAT mapping list required")
    if len(assignments)>256:
        raise FirewallPreviewError("Too many IPs")
    known=set()
    rendered=[]
    for entry in assignments:
        if not isinstance(entry,dict) or set(entry)!={"ip","peer"}:
            raise FirewallPreviewError("Invalid routed entry")
        public=ipv4(entry["ip"],global_only=True)
        name=entry["peer"]
        if public==admin or public in known:
            raise FirewallPreviewError("Public IP is management or duplicate")
        known.add(public)
        if not isinstance(name,str) or name not in peers:
            raise FirewallPreviewError("Unknown peer")
        peer=peers[name]
        if not isinstance(peer,dict):
            raise FirewallPreviewError("Invalid peer")
        ipv4(peer.get("ip"),private_only=True)
        if any(not isinstance(m,dict) or m.get("public_ip")==public
               for m in legacy_nat_mappings):
            raise FirewallPreviewError("Active or unrecognized NAT mapping")
        rendered.append((public,name))
    rendered.sort()
    return {
        "mode":"routed-wg",
        "execution_supported":False,
        "prepared_for_review":True,
        "forward_before_wan_drop":[
            f'iifname "{wan}" oifname "{wg}" ip daddr {ip} accept'
            for ip,_ in rendered
        ],
        "forward_before_wg_drop":[
            f'iifname "{wg}" oifname "{wan}" ip saddr {ip} accept'
            for ip,_ in rendered
        ],
        "gateway_input_drop":[
            f'iifname "{wan}" ip daddr {ip} drop'
            for ip,_ in rendered
        ],
        "public_ip_destinations":[
            {"ip":ip,"peer":name,"vpn_ip":str(peers[name]["ip"])}
            for ip,name in rendered
        ],
        "preconditions":[
            "Independent rollback timers are armed on peer and gateway",
            "Gateway no longer owns the public IP locally",
            "AllowedIPs includes the public /32 on the intended WG peer",
            "A host route to public /32 goes via the correct WG peer",
            "Peer owns public /32 and has exact source-policy route via WG",
            "Peer host firewall explicitly protects public services",
            "Existing NAT maps are migrated; nft table regeneration is upgraded",
            "External ingress and source-egress tests succeed before confirmation",
        ],
        "live_network_modified":False,
    }

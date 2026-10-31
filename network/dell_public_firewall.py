"""Pure preview of host INPUT firewall for a Dell routed public IPv4 /32.

Does not execute nft, ip, wg, subprocess or open files. The generated table
is dedicated to the routed public IPv4, and leaves Tailscale/VPN/LAN alone.
A separate privileged, independently tested transaction/rollback system is
required for deployment. No interface changes are possible here.
"""
from __future__ import annotations
import ipaddress
import re

IFACE=re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class PublicFirewallPlanError(ValueError):
    pass


def preview(public_ip, wg, tcp_ports=(22,), udp_ports=()):
    try:
        addr=ipaddress.ip_address(public_ip)
    except (ValueError,TypeError) as exc:
        raise PublicFirewallPlanError("Adresse publique invalide") from exc
    if addr.version!=4 or not addr.is_global:
        raise PublicFirewallPlanError("IPv4 globale uniquement")
    if not isinstance(wg,str) or not IFACE.fullmatch(wg):
        raise PublicFirewallPlanError("Interface WireGuard invalide")
    if not isinstance(tcp_ports,(tuple,list)) or not isinstance(udp_ports,(tuple,list)):
        raise PublicFirewallPlanError("Liste des ports invalide")
    def portset(values):
        if len(values)>64 or any(type(p) is not int or not 1<=p<=65535 for p in values):
            raise PublicFirewallPlanError("Ports hors limites")
        if len(values)!=len(set(values)):
            raise PublicFirewallPlanError("Port dupliqué")
        return sorted(values)
    tcp=portset(tcp_ports)
    udp=portset(udp_ports)
    if 22 not in tcp:
        raise PublicFirewallPlanError("SSH 22 doit rester accessible à l'étape de test")
    ip=str(addr)
    lines=[
        "table ip cerato_peer_public {",
        "  chain input {",
        "    type filter hook input priority -50; policy accept;",
        f'    iifname "{wg}" ip daddr {ip} ct state established,related accept',
    ]
    for proto,ports in (("tcp",tcp),("udp",udp)):
        for port in ports:
            lines.append(f'    iifname "{wg}" ip daddr {ip} {proto} dport {port} accept')
    lines.extend([
        f'    iifname "{wg}" ip daddr {ip} drop',
        "  }",
        "}",
        "",
    ])
    return {
        "format":"cerato-dell-public-firewall-preview-v1",
        "public_ip":ip,
        "tunnel":wg,
        "allow_tcp":tcp,
        "allow_udp":udp,
        "nft_script":"\n".join(lines),
        "applied":False,
        "ready_for_install":False,
        "requires_persistent_rollback":True,
        "notes":[
            "This additional base chain can still be affected by other nft/ufw chains.",
            "Traffic on Tailscale, WireGuard private IPv4 and LAN remains outside these matches.",
            "No IPv6 protection is claimed.",
            "Test SSH public and existing service access externally before commit.",
        ],
    }

"""Portable, no-side-effect network planner for Cerato Network.

Rendering is pure: this module NEVER executes nft, wg, ip or systemctl. A future
privileged local service must independently validate, check and apply a plan
with backup/rollback and an SSH keepalive safeguard.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
import ipaddress
import re

IFACE=re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
NAME=re.compile(r"^[a-z][a-z0-9-]{0,39}$")
PROTOCOLS={"tcp","udp"}


class NetworkPlanError(ValueError):
    pass


def ipv4(value, public=False):
    try:
        addr=ipaddress.ip_address(value)
    except (ValueError,TypeError):
        raise NetworkPlanError("IPv4 invalide")
    if addr.version!=4 or (public and not addr.is_global):
        raise NetworkPlanError("Adresse IPv4 publique invalide")
    return str(addr)


def iface(name):
    if not isinstance(name,str) or not IFACE.fullmatch(name):
        raise NetworkPlanError("Interface invalide")
    return name


def public_key(value):
    if not isinstance(value,str):
        raise NetworkPlanError("Clé WireGuard invalide")
    try:
        decoded=base64.b64decode(value,validate=True)
    except (ValueError,TypeError):
        raise NetworkPlanError("Clé WireGuard invalide")
    if len(decoded)!=32:
        raise NetworkPlanError("Clé WireGuard invalide")
    return value


def tcpudp_port(port):
    try:
        val=int(port)
    except (ValueError,TypeError):
        raise NetworkPlanError("Port invalide")
    if not (1<=val<=65535):
        raise NetworkPlanError("Port hors limites")
    return val


@dataclass(frozen=True)
class Peer:
    name: str
    private_ip: str
    key: str


@dataclass(frozen=True)
class Publication:
    public_ip: str
    peer: str
    protocol: str
    public_port: int
    destination_port: int


class Plan:
    def __init__(self, *, wan_iface: str, tunnel_iface: str,
                 gateway_tunnel_ip: str, cidr: str, primary_ipv4: str):
        self.wan=iface(wan_iface)
        self.tunnel=iface(tunnel_iface)
        if self.wan==self.tunnel:
            raise NetworkPlanError("Interfaces WAN et tunnel identiques")
        try:
            self.subnet=ipaddress.ip_network(cidr,strict=True)
        except ValueError:
            raise NetworkPlanError("CIDR du tunnel invalide")
        if self.subnet.version!=4 or self.subnet.prefixlen<16 or self.subnet.prefixlen>30:
            raise NetworkPlanError("Réseau tunnel IPv4 invalide")
        self.gateway=ipv4(gateway_tunnel_ip)
        if ipaddress.ip_address(self.gateway) not in self.subnet:
            raise NetworkPlanError("Passerelle hors du tunnel")
        self.primary=ipv4(primary_ipv4,public=True)
        self.extra_ips=set()
        self.peers={}
        self.publications={}
        self.public_routes={}

    def add_public_ip(self, ip: str, *, provider_confirmed: bool=False,
                      present_on_wan: bool=False):
        address=ipv4(ip,public=True)
        if address==self.primary:
            raise NetworkPlanError("IPv4 principale réservée à l'administration")
        if not provider_confirmed or not present_on_wan:
            raise NetworkPlanError("Adresse non attribuée par l'hébergeur ou absente du WAN")
        self.extra_ips.add(address)

    def add_peer(self, name: str, tunnel_ip: str, pubkey: str):
        if not isinstance(name,str) or not NAME.fullmatch(name):
            raise NetworkPlanError("Nom de machine invalide")
        dest=ipv4(tunnel_ip)
        addr=ipaddress.ip_address(dest)
        if addr not in self.subnet or dest==self.gateway or dest in {str(self.subnet.network_address),str(self.subnet.broadcast_address)}:
            raise NetworkPlanError("IP de tunnel interdite")
        wireguard_key=public_key(pubkey)
        if name in self.peers:
            raise NetworkPlanError("Nom de machine déjà utilisé")
        if any(p.private_ip==dest or p.key==wireguard_key for p in self.peers.values()):
            raise NetworkPlanError("IP de tunnel ou clé déjà utilisée")
        self.peers[name]=Peer(name,dest,wireguard_key)

    def route_public_ip(self, public_ip: str, peer: str):
        """Declare an exclusive routed /32 assignment; NEVER change the host.

        This reserves the IPv4 for an agent-backed, policy-routed tunnel.
        Gateway alias migration, WireGuard AllowedIPs, host forwarding,
        firewall and SSH recovery are not performed by this model.
        """
        ip=ipv4(public_ip,public=True)
        if ip not in self.extra_ips:
            raise NetworkPlanError("IPv4 supplémentaire non enregistrée")
        if peer not in self.peers:
            raise NetworkPlanError("Machine inconnue")
        if ip in self.public_routes:
            raise NetworkPlanError("IPv4 déjà attribuée en mode routé")
        if any(mapping.public_ip==ip for mapping in self.publications.values()):
            raise NetworkPlanError("Supprimer ou migrer les publications NAT avant le routage")
        self.public_routes[ip]=peer

    def routed_preview(self):
        """Declarative plan only: no direct ip, wg, nft or systemctl actions.

        A future privileged agent must independently validate and apply the
        plan, verify external connectivity, and restore the original network
        state automatically on health-check failure.
        """
        return {
            "mode":"routed-wg",
            "applicable":False,
            "reason":"Agent distant et basculement avec rollback non implémentés",
            "gateway":[
                {"public_ip":ip, "target_peer":peer,
                 "tunnel_destination":self.peers[peer].private_ip,
                 "public_cidr":ip+"/32",
                 "require_peer_allowed_ips":[self.peers[peer].private_ip+"/32", ip+"/32"],
                 "requires_local_wan_alias_migration":True,
                 "requires_public_ip_forwarding_firewall":True}
                for ip,peer in sorted(self.public_routes.items())
            ],
            "agents":[
                {"peer":peer,"public_ip":ip,"prefix":32,
                 "tunnel_interface":self.tunnel,
                 "source_policy_routing_required":True,
                 "preserve_existing_default_route":True,
                 "host_firewall_controls_exposed_ports":True}
                for ip,peer in sorted(self.public_routes.items())
            ],
            "safety":[
                "external_management_access_required",
                "tunnel_and_host_agent_health_checks",
                "backup_and_timed_rollback_required",
                "provider_assignment_confirmation_required",
                "no_exposure_of_management_ip",
            ],
        }

    def publish(self, public_ip: str, peer: str, proto: str,
                public_port: int, destination_port: int):
        ip=ipv4(public_ip,public=True)
        if ip not in self.extra_ips:
            raise NetworkPlanError("Utilise une IPv4 supplémentaire validée")
        if ip in self.public_routes:
            raise NetworkPlanError("IPv4 routée : gérer les ports sur la machine, sans NAT")
        if not isinstance(peer,str) or peer not in self.peers:
            raise NetworkPlanError("Machine inconnue")
        if proto not in PROTOCOLS:
            raise NetworkPlanError("Protocole inconnu")
        external=tcpudp_port(public_port)
        internal=tcpudp_port(destination_port)
        if external in (22,23,25,53,110,143,445,3306,5432,6379,8006,8787,51820):
            raise NetworkPlanError("Port sensible refusé par défaut")
        key=(ip,proto,external)
        if key in self.publications:
            raise NetworkPlanError("Conflit sur la publication")
        self.publications[key]=Publication(ip,peer,proto,external,internal)

    def nft_text(self):
        """Generate a dedicated nftables table, not a global firewall flush.

        This text is a preview only. It intentionally does not include a
        preamble that deletes or replaces any pre-existing production table.
        """
        lines=[
            "table ip cerato_network {",
            "  chain prerouting {",
            "    type nat hook prerouting priority dstnat; policy accept;",
        ]
        for m in sorted(self.publications.values(),key=lambda x:(x.public_ip,x.protocol,x.public_port)):
            dest=self.peers[m.peer].private_ip
            lines.append(f'    iifname "{self.wan}" ip daddr {m.public_ip} {m.protocol} dport {m.public_port} dnat to {dest}:{m.destination_port}')
        # Intentionally NO FORWARD/INPUT/OUTPUT policy: a generic DNAT match
        # must not introduce a blanket forwarding bypass. Per-publication
        # forwarding rules require a separate, reviewed firewall adapter.
        lines += ["  }", "}"]
        return "\n".join(lines)+"\n"

    def serializable(self):
        return {
            "wan_if":self.wan,"wg_if":self.tunnel,
            "primary_ipv4":self.primary,"tunnel_cidr":str(self.subnet),
            "gateway_tunnel_ip":self.gateway,
            "extra_ipv4":sorted(self.extra_ips),
            "peers":[p.__dict__ for p in self.peers.values()],
            "publications":[m.__dict__ for m in self.publications.values()],
            "routed_public_ipv4":self.routed_preview(),
        }

"""Safe, pure command planning for a Dell routed IPv4 /32 peer transaction.

No command execution. An independently audited privileged agent with persistent
rollback must verify preconditions before using these plans on a live machine.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import re

DEVICE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")


class PeerPlanError(ValueError):
    pass


@dataclass(frozen=True)
class PeerTarget:
    public_ip: str
    vpn_ip: str
    tunnel: str
    route_table: int
    rule_priority: int

    def validate(self):
        try:
            pub = ipaddress.ip_address(self.public_ip)
            vpn = ipaddress.ip_address(self.vpn_ip)
        except (TypeError, ValueError) as exc:
            raise PeerPlanError("IP mal formée") from exc
        if pub.version != 4 or not pub.is_global:
            raise PeerPlanError("IPv4 publique incorrecte")
        if vpn.version != 4 or not vpn.is_private or pub == vpn:
            raise PeerPlanError("IP VPN incorrecte")
        if not isinstance(self.tunnel,str) or not DEVICE.fullmatch(self.tunnel):
            raise PeerPlanError("Interface WG incorrecte")
        if type(self.route_table) is not int or not 256 <= self.route_table <= 0xFFFFFFFF:
            raise PeerPlanError("Table de routage invalide")
        if type(self.rule_priority) is not int or not 1000 <= self.rule_priority < 5000:
            raise PeerPlanError("Priorité réseau invalide")
        return self


@dataclass(frozen=True)
class PeerObserved:
    vpn_ip_on_tunnel: bool
    public_ip_owner: str | None
    source_vpn_uses_tunnel: bool
    routing_table_has_default_wg: bool
    priority_available: bool
    rp_filter_non_strict: bool
    access_recovery_tested: bool


def render_peer_stage(target: PeerTarget, observed: PeerObserved):
    target.validate()
    if not isinstance(observed, PeerObserved):
        raise PeerPlanError("État réel du pair non fourni")
    flags = {
        "vpn_ip_on_tunnel":observed.vpn_ip_on_tunnel,
        "public_ip_unassigned":observed.public_ip_owner is None,
        "source_vpn_uses_tunnel":observed.source_vpn_uses_tunnel,
        "routing_table_has_default_wg":observed.routing_table_has_default_wg,
        "priority_available":observed.priority_available,
        "rp_filter_non_strict":observed.rp_filter_non_strict,
        "access_recovery_tested":observed.access_recovery_tested,
    }
    if any(type(x) is not bool for x in flags.values()):
        raise PeerPlanError("Prérequis non booléens")
    errors = sorted(k for k,ok in flags.items() if not ok)
    if errors:
        return {"ready":False, "issues":errors, "operations":[], "rollback":[]}
    prefix=target.public_ip+"/32"
    # Only two additive actions are specified; no default route, SSH or Tailscale changes.
    additions=[
        ["ip","-4","address","add",prefix,"dev",target.tunnel],
        ["ip","-4","rule","add","pref",str(target.rule_priority),
         "from",prefix,"table",str(target.route_table)]
    ]
    reversals=[
        ["ip","-4","rule","del","pref",str(target.rule_priority),
         "from",prefix,"table",str(target.route_table)],
        ["ip","-4","address","del",prefix,"dev",target.tunnel]
    ]
    return {
        "ready":True,
        "issues":[],
        "operations":additions,
        "rollback":reversals,
        "requires_external_independent_watchdog":True,
        "requires_explicit_gateway_cutover":True,
        "operator_only":True,
        "executed":False,
        "persistent":False,
        "source_route_test":["ip","-4","route","get","1.1.1.1","from",target.public_ip],
    }

"""Read-only gateway cutover contract for moving an OVH Additional IPv4 /32.

This is not a privileged installer; it deliberately refuses to emit an
executable migration when there are legacy NAT mappings or unknown filters.
No automatic modification of the production nftables table is authorized.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import re

NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")


class GatewayPlanError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayTarget:
    public_ip: str
    gateway_primary_ip: str
    peer_vpn_ip: str
    wan: str
    wireguard: str


@dataclass(frozen=True)
class GatewayObserved:
    provider_assignment_verified: bool
    public_alias_on_wan: bool
    peer_allowed_ips_have_public_32: bool
    peer_is_online: bool
    ipv4_forward_enabled: bool
    forward_rules_reviewed: bool
    nat_mapping_count: int
    gateway_backup_verified: bool
    peer_stage_confirmed: bool
    independent_rollback_armed: bool
    external_test_ready: bool


def plan_gateway(target, state):
    if not isinstance(target, GatewayTarget) or not isinstance(state, GatewayObserved):
        raise GatewayPlanError("Paramètres d'audit invalides")
    try:
        pub = ipaddress.ip_address(target.public_ip)
        private = ipaddress.ip_address(target.peer_vpn_ip)
        management = ipaddress.ip_address(target.gateway_primary_ip)
    except (TypeError,ValueError) as e:
        raise GatewayPlanError("IPv4 incorrecte") from e
    if (pub.version != 4 or management.version != 4 or private.version != 4
            or not pub.is_global or not management.is_global or pub == management
            or not private.is_private):
        raise GatewayPlanError("Adresse publique ou pair incorrect")
    for interface in (target.wan,target.wireguard):
        if not isinstance(interface,str) or not NAME.fullmatch(interface):
            raise GatewayPlanError("Interface invalide")
    if target.wan == target.wireguard:
        raise GatewayPlanError("Interface WAN identique au tunnel")
    if type(state.nat_mapping_count) is not int or state.nat_mapping_count < 0:
        raise GatewayPlanError("Nombre de NAT invalide")
    checks={
        "provider_assignment_verified":state.provider_assignment_verified,
        "public_alias_on_wan":state.public_alias_on_wan,
        "peer_allowed_ips_have_public_32":state.peer_allowed_ips_have_public_32,
        "peer_is_online":state.peer_is_online,
        "ipv4_forward_enabled":state.ipv4_forward_enabled,
        "forward_rules_reviewed":state.forward_rules_reviewed,
        "no_active_nat_mapping":state.nat_mapping_count == 0,
        "gateway_backup_verified":state.gateway_backup_verified,
        "peer_stage_confirmed":state.peer_stage_confirmed,
        "independent_rollback_armed":state.independent_rollback_armed,
        "external_test_ready":state.external_test_ready,
    }
    if any(type(v) is not bool for v in checks.values()):
        raise GatewayPlanError("Observations non vérifiables")
    remaining=sorted(k for k,v in checks.items() if not v)
    return {
        "mode":"routed-wg",
        "public_ip":str(pub),
        "management_ip_preserved":str(management),
        "peer_ip":str(private),
        "prerequisites":checks,
        "blockers":remaining,
        "ready_for_operator_review":not remaining,
        "requires_nat_transaction_with_rollback":state.nat_mapping_count > 0,
        "allow_apply":False,
        "implemented":False,
        "automatically_migrated":False,
        "changes_existing_wan_alias":False,
        "changes_existing_wireguard_config":False,
        "changes_existing_firewall":False,
    }

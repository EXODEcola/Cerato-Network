"""Cerato Network routed /32 cutover readiness, pure and fail-closed.

This module is intentionally NOT a network adapter. It never uses subprocess,
nft, wg, ip, systemctl, SSH or an external API. A privileged application must
treat this as an input validator only, never as proof of deployed connectivity.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

IFACE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")


class ReadinessError(ValueError):
    pass


def ipv4(value, *, public=False):
    if not isinstance(value, str):
        raise ReadinessError("Adresse IPv4 invalide")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ReadinessError("Adresse IPv4 invalide") from exc
    if addr.version != 4 or (public and not addr.is_global):
        raise ReadinessError("Adresse IPv4 publique requise")
    return str(addr)


def interface(value):
    if not isinstance(value, str) or not IFACE.fullmatch(value):
        raise ReadinessError("Interface invalide")
    return value


@dataclass(frozen=True)
class GatewayObservation:
    public_ip_on_wan: bool
    provider_attached: bool
    wg_peer_handshake_recent: bool
    route_to_vpn_peer_via_wg: bool
    forwarding_enabled: bool
    live_nat_mappings: int
    forward_policy_reviewed: bool


@dataclass(frozen=True)
class PeerObservation:
    vpn_source_route_via_wg: bool
    existing_default_route_preserved: bool
    rp_filter_effective: int
    ssh_listening: bool
    ssh_keys_only: bool
    firewall_reviewed: bool
    trusted_recovery_access: bool
    agent_connected: bool


@dataclass(frozen=True)
class Recovery:
    backup_verified: bool
    console_access_verified: bool
    watchdog_on_gateway: bool
    watchdog_on_peer: bool
    signed_compatible_release: bool
    outside_probe_available: bool


def _bools(instance):
    for k, v in vars(instance).items():
        if k == "rp_filter_effective" or k == "live_nat_mappings":
            continue
        if type(v) is not bool:
            raise ReadinessError("Mesure non booléenne: " + k)


def assess(public_ip, vpn_ip, wan_if, wg_if, gateway, peer, recovery):
    """Produce facts and outstanding gates, without changing any machine.

    Any missing observation is a blocker; human review can refine the facts
    but must not silently mark an unchecked condition as successful.
    """
    public_ip = ipv4(public_ip, public=True)
    vpn_ip = ipv4(vpn_ip)
    wan_if = interface(wan_if)
    wg_if = interface(wg_if)
    if wan_if == wg_if:
        raise ReadinessError("WAN et tunnel identiques")
    if not isinstance(gateway, GatewayObservation) or not isinstance(peer, PeerObservation):
        raise ReadinessError("Observations incomplètes")
    if not isinstance(recovery, Recovery):
        raise ReadinessError("Plan de secours manquant")
    for record in (gateway, peer, recovery):
        _bools(record)
    if type(gateway.live_nat_mappings) is not int or gateway.live_nat_mappings < 0:
        raise ReadinessError("Comptage NAT invalide")
    if type(peer.rp_filter_effective) is not int or peer.rp_filter_effective not in (0, 1, 2):
        raise ReadinessError("État rp_filter invalide")

    requirements = {
        "provider_attached": gateway.provider_attached,
        "additional_ip_on_gateway": gateway.public_ip_on_wan,
        "wg_handshake_recent": gateway.wg_peer_handshake_recent,
        "vpn_route": gateway.route_to_vpn_peer_via_wg,
        "ipv4_forward": gateway.forwarding_enabled,
        "gateway_forward_filter_review": gateway.forward_policy_reviewed,
        "peer_vpn_policy_route": peer.vpn_source_route_via_wg,
        "peer_default_route_preserved": peer.existing_default_route_preserved,
        "peer_rp_filter_non_strict": peer.rp_filter_effective != 1,
        "ssh_listening": peer.ssh_listening,
        "ssh_keys_only": peer.ssh_keys_only,
        "peer_firewall_review": peer.firewall_reviewed,
        "recovery_access": peer.trusted_recovery_access,
        "agent_online": peer.agent_connected,
        "verified_backup": recovery.backup_verified,
        "console_recovery": recovery.console_access_verified,
        "gateway_watchdog": recovery.watchdog_on_gateway,
        "peer_watchdog": recovery.watchdog_on_peer,
        "signed_compatibility": recovery.signed_compatible_release,
        "external_probe": recovery.outside_probe_available,
        "nat_migration_plan": gateway.live_nat_mappings == 0,
    }
    pending = sorted(key for key, ok in requirements.items() if not ok)
    return {
        "schema": "cerato-routed-ip-readiness-v1",
        "public_ip": public_ip,
        "vpn_ip": vpn_ip,
        "wan_if": wan_if,
        "wg_if": wg_if,
        "role": "gateway-to-peer",
        "mode": "routed-wg",
        "checks": requirements,
        "blockers": pending,
        "ready_for_review": not pending,
        # Always false: final authorization is a separate privileged workflow.
        "enabled": False,
        "apply_allowed": False,
        "migration": [
            "Preserve management IPv4 and legacy SSH/Tailscale",
            "Prepare peer /32 and source-specific routing in isolation",
            "Prepare WireGuard cryptokey /32 route and reviewed FORWARD filters",
            "Migrate all current NAT publications and gateway /32 alias together",
            "Verify externally both SSH, TCP/UDP and outbound source IPv4",
            "Confirm peer and gateway rollback watchdogs independently",
        ],
        "post_deploy_validation_required": True,
    }

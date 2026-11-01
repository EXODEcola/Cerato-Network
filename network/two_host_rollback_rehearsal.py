"""Entirely in-memory, deterministic two-host /32 migration and rollback rehearsal.

This is a logic test, NOT a deployable gateway/peer agent. All steps modify
local Python dictionaries only; no process, network, file, systemd or timer
calls. Failure injection exercises restoration of both independent host
snapshots. A real rollback service must be separately implemented and tested.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

STEPS=(
    "simulate_gateway_watchdog_armed",
    "simulate_peer_watchdog_armed",
    "simulate_peer_public_firewall",
    "simulate_peer_public_address",
    "simulate_peer_source_policy",
    "simulate_gateway_cryptokey_allowed_ips",
    "simulate_gateway_public_host_route",
    "simulate_gateway_persistent_config_conversion",
    "simulate_gateway_routed_filter",
    "simulate_gateway_remove_wan_alias",
)

INITIAL_GATEWAY={
    "additional_ip_local_on_wan":True,
    "nat_public_8080":True,
    "peer_allows_public_32":False,
    "public_host_route_via_wg":False,
    "persistent_mode":"local-nat",
    "routed_forward_filter":False,
    "management_ipv4_preserved":True,
}
INITIAL_PEER={
    "public_firewall_staged":False,
    "public_32_on_wg":False,
    "public_source_rule":False,
    "tailscale_preserved":True,
    "lan_default_route_preserved":True,
    "ipv6_unchanged":True,
}


class RehearsalError(ValueError):
    pass


@dataclass(frozen=True)
class Rehearsal:
    result: str
    failure_step: str | None
    attempted: tuple[str,...]
    rollback_order: tuple[str,...]
    gateway_restored: bool
    peer_restored: bool
    management_ip_preserved: bool
    tailscale_preserved: bool
    external_connectivity_proven: bool=False
    network_modified: bool=False
    rollout_authorized: bool=False


def rehearse(*, fail_after: str | None=None) -> Rehearsal:
    """Simulate success or failure injected after any single step."""
    if fail_after is not None and fail_after not in STEPS:
        raise RehearsalError("Étape de défaillance inconnue")
    g=deepcopy(INITIAL_GATEWAY)
    p=deepcopy(INITIAL_PEER)
    snapshots=(deepcopy(g),deepcopy(p))
    armed={"gateway":False,"peer":False}
    attempted=[]
    rollback=[]
    try:
        for step in STEPS:
            if step=="simulate_gateway_watchdog_armed":
                armed["gateway"]=True
            elif step=="simulate_peer_watchdog_armed":
                armed["peer"]=True
            else:
                if not all(armed.values()):
                    raise RehearsalError("Watchdogs indépendants non armés")
                if step=="simulate_peer_public_firewall":
                    p["public_firewall_staged"]=True
                elif step=="simulate_peer_public_address":
                    if not p["public_firewall_staged"]:
                        raise RehearsalError("Pare-feu Dell non configuré")
                    p["public_32_on_wg"]=True
                elif step=="simulate_peer_source_policy":
                    if not p["public_32_on_wg"]:
                        raise RehearsalError("Adresse publique Dell absente")
                    p["public_source_rule"]=True
                elif step=="simulate_gateway_cryptokey_allowed_ips":
                    g["peer_allows_public_32"]=True
                elif step=="simulate_gateway_public_host_route":
                    if not g["peer_allows_public_32"]:
                        raise RehearsalError("AllowedIPs publiques manquantes")
                    g["public_host_route_via_wg"]=True
                elif step=="simulate_gateway_persistent_config_conversion":
                    if not (p["public_source_rule"] and
                            g["public_host_route_via_wg"]):
                        raise RehearsalError("Route retour non prête")
                    g["persistent_mode"]="routed-wg"
                    g["nat_public_8080"]=False
                elif step=="simulate_gateway_routed_filter":
                    if g["persistent_mode"]!="routed-wg":
                        raise RehearsalError("État persistant non migré")
                    g["routed_forward_filter"]=True
                elif step=="simulate_gateway_remove_wan_alias":
                    if not g["routed_forward_filter"]:
                        raise RehearsalError("FORWARD public non configuré")
                    g["additional_ip_local_on_wan"]=False
            attempted.append(step)
            if step==fail_after:
                raise RehearsalError("Panne simulée après "+step)
        # Simulated success never demonstrates real-world connectivity.
        return Rehearsal(
            "simulated_ready_for_external_probes",None,tuple(attempted),tuple(),
            gateway_restored=False,peer_restored=False,
            management_ip_preserved=g["management_ipv4_preserved"],
            tailscale_preserved=p["tailscale_preserved"],
        )
    except RehearsalError:
        # The two watchdogs are independent. Each resets only local state.
        # No cross-host connectivity is needed for either local reset.
        g=deepcopy(snapshots[0])
        rollback.append("gateway_local_snapshot_restored")
        p=deepcopy(snapshots[1])
        rollback.append("peer_local_snapshot_restored")
        armed={"gateway":False,"peer":False}
        return Rehearsal(
            "simulated_rolled_back",fail_after,tuple(attempted),tuple(rollback),
            gateway_restored=(g==INITIAL_GATEWAY),
            peer_restored=(p==INITIAL_PEER),
            management_ip_preserved=g["management_ipv4_preserved"],
            tailscale_preserved=p["tailscale_preserved"],
        )


def report(result:Rehearsal):
    if not isinstance(result,Rehearsal):
        raise RehearsalError("Rapport invalide")
    return {
        "schema":"cerato-two-host-rollback-rehearsal-v1",
        "result":result.result,
        "failure_injected_at":result.failure_step,
        "steps_attempted":list(result.attempted),
        "rollback_order":list(result.rollback_order),
        "gateway_restored_in_memory":result.gateway_restored,
        "peer_restored_in_memory":result.peer_restored,
        "gateway_management_preserved_in_memory":result.management_ip_preserved,
        "peer_tailscale_preserved_in_memory":result.tailscale_preserved,
        "external_connectivity_proven":False,
        "network_modified":False,
        "agents_installed":False,
        "rollout_authorized":False,
    }

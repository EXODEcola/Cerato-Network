"""Cerato Additional IPv4 two-host cutover / rollback *protocol contract*.

Pure state transition validator: no privileged calls, clock, file writes,
background jobs, SSH, systemd, WireGuard, nftables, network or tokens.
This is NOT a cutover agent and its return values never grant permission to
apply production changes. A separate independently tested privileged
controller is required before any deployment.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress
import re
from typing import FrozenSet

TX_ID=re.compile(r"^[a-f0-9]{32}$")
HOSTS=frozenset(("gateway","peer"))
EVENTS={
    "gateway": frozenset(("snapshot_verified","watchdog_armed",
                          "stage_verified","rollback_drill_passed")),
    "peer": frozenset(("snapshot_verified","watchdog_armed",
                       "stage_verified","rollback_drill_passed",
                       "firewall_reviewed","ipv6_exposure_reviewed",
                       "tailscale_recovery_tested")),
}
HEALTH=frozenset(("external_ssh_publickey_success",
                   "external_ipv4_ingress_success",
                   "public_ipv4_egress_source_verified",
                   "both_hosts_reachable_via_recovery",
                   "no_stale_nat_or_alias",
                   "current_pair_cryptokey_verified"))
PREREQUISITES=(
    "gateway.snapshot_verified",
    "gateway.watchdog_armed",
    "gateway.stage_verified",
    "gateway.rollback_drill_passed",
    "peer.snapshot_verified",
    "peer.watchdog_armed",
    "peer.stage_verified",
    "peer.rollback_drill_passed",
    "peer.firewall_reviewed",
    "peer.ipv6_exposure_reviewed",
    "peer.tailscale_recovery_tested",
)
PHASES=("plan","prepared","armed","cutover_pending","verifying","committed",
        "rollback_required","rolled_back")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Protocol:
    transaction_id: str
    public_ip: str
    management_ip: str
    phase: str="plan"
    proofs: FrozenSet[str]=frozenset()
    checks: FrozenSet[str]=frozenset()
    operator_authorized: bool=False
    deadline_seconds: int=300

    def __post_init__(self):
        if not isinstance(self.transaction_id,str) or not TX_ID.fullmatch(self.transaction_id):
            raise ProtocolError("Identifiant transaction invalide")
        try:
            public=ipaddress.IPv4Address(self.public_ip)
            admin=ipaddress.IPv4Address(self.management_ip)
        except (TypeError,ValueError) as exc:
            raise ProtocolError("IPv4 non conforme") from exc
        if (not public.is_global or not admin.is_global or public==admin):
            raise ProtocolError("IPv4 administrateur ou publique incorrecte")
        if self.phase not in PHASES:
            raise ProtocolError("Phase inconnue")
        if (type(self.deadline_seconds) is not int or
                not 120<=self.deadline_seconds<=900):
            raise ProtocolError("Délai rollback invalide")
        if type(self.operator_authorized) is not bool:
            raise ProtocolError("Autorisation opérateur non booléenne")
        if (not isinstance(self.proofs,frozenset) or
                not isinstance(self.checks,frozenset)):
            raise ProtocolError("Certificats de contrôle mal formés")
        expected=frozenset(PREREQUISITES)
        if not self.proofs.issubset(expected) or not self.checks.issubset(HEALTH):
            raise ProtocolError("Preuves non reconnues")


def observe(protocol: Protocol, host: str, event: str) -> Protocol:
    """Record *reported* preparation evidence only; attestations not trusted."""
    if not isinstance(protocol,Protocol) or protocol.phase not in ("plan","prepared"):
        raise ProtocolError("Phase incompatible avec les prérequis")
    if host not in HOSTS or event not in EVENTS[host]:
        raise ProtocolError("Hôte ou observation non approuvé")
    return replace(protocol, proofs=protocol.proofs|{host+"."+event})


def authorize_operator(protocol:Protocol, authorized:bool)->Protocol:
    if not isinstance(protocol,Protocol) or protocol.phase!="prepared" or authorized is not True:
        raise ProtocolError("Autorisation impossible sans préparation")
    return replace(protocol,operator_authorized=True)


def transition(protocol:Protocol, action:str)->Protocol:
    if not isinstance(protocol,Protocol):
        raise ProtocolError("Transaction non conforme")
    if action=="prepare":
        if protocol.phase!="plan" or not set(PREREQUISITES).issubset(protocol.proofs):
            raise ProtocolError("Préparation Dell/OVH/IPv6/watchdogs incomplète")
        return replace(protocol,phase="prepared")
    if action=="arm":
        if protocol.phase!="prepared" or not protocol.operator_authorized:
            raise ProtocolError("Autorisation d'armement absente")
        return replace(protocol,phase="armed")
    if action=="start_cutover":
        if protocol.phase!="armed":
            raise ProtocolError("Watchdogs non armés")
        return replace(protocol,phase="cutover_pending")
    if action=="start_verification":
        if protocol.phase!="cutover_pending":
            raise ProtocolError("Basculement non déclaré")
        return replace(protocol,phase="verifying")
    if action=="commit":
        if protocol.phase!="verifying" or protocol.checks!=HEALTH:
            raise ProtocolError("Vérifications externes et récupération non confirmées")
        return replace(protocol,phase="committed")
    if action=="rollback":
        if protocol.phase in ("committed","rolled_back","plan"):
            raise ProtocolError("Rollback hors phase")
        return replace(protocol,phase="rollback_required")
    if action=="rollback_confirmed":
        if protocol.phase!="rollback_required":
            raise ProtocolError("Restitution non prouvée")
        return replace(protocol,phase="rolled_back")
    raise ProtocolError("Transition non prévue")


def verify(protocol:Protocol,name:str)->Protocol:
    if not isinstance(protocol,Protocol) or protocol.phase!="verifying" or name not in HEALTH:
        raise ProtocolError("Vérification non autorisée")
    return replace(protocol,checks=protocol.checks|{name})


def describe(protocol:Protocol):
    if not isinstance(protocol,Protocol):
        raise ProtocolError("Transaction non conforme")
    return {
        "format":"cerato-two-host-cutover-contract-v1",
        "transaction_id":protocol.transaction_id,
        "public_ip":protocol.public_ip,
        "management_ip":protocol.management_ip,
        "phase":protocol.phase,
        "remaining_prepare":sorted(set(PREREQUISITES)-set(protocol.proofs)),
        "remaining_commit_checks":sorted(HEALTH-protocol.checks),
        "rollback_timeout_seconds":protocol.deadline_seconds,
        "operator_authorized":protocol.operator_authorized,
        "live_network_modified":False,
        "agent_installed":False,
        "watchdog_actually_armed":False,
        "authorization_to_apply":False,
        "note":"This protocol models ordering only; it cannot verify proofs, install watchdogs, or start a real cutover.",
    }

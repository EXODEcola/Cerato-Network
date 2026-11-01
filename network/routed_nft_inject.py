"""Safe read-only overlay for the historical Cerato nftables renderer.

No invocation of nft, WireGuard, iproute2 or systemd. Accept exact individual
or literal-set INPUT drops (the live controller uses a literal IPv4 pool set).
Never remove or weaken gateway INPUT protection.
"""
from __future__ import annotations

import ipaddress
import re

try:
    from .routed_firewall import routed_rules, FirewallPreviewError
except ImportError:
    from routed_firewall import routed_rules, FirewallPreviewError


class LegacyFirewallError(ValueError):
    pass


def _exact_drop(text, incoming, outgoing):
    pattern = (
        r'(?m)^[ \t]*iifname "' + re.escape(incoming) +
        r'"[ \t]+oifname "' + re.escape(outgoing) +
        r'"[ \t]+drop[ \t]*(?:#[^\n]*)?$'
    )
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise LegacyFirewallError("DROP FORWARD historique manquant ou dupliqué")
    return found[0]


def guarded_public_ips(nft_text, wan):
    """Extract and verify one precise gateway INPUT drop for Cerato pool IPv4.

    Accepted: ip daddr 54.37.165.151 drop
              ip daddr { 54.37.165.151, 54.37.165.152 } drop
    CIDRs, ranges, unmatched lines, duplicate addresses or ambiguous chains
    fail closed. Returns (frozenset of IPv4 strings, exact original guard).
    """
    if not isinstance(nft_text, str) or len(nft_text) > 1_000_000:
        raise LegacyFirewallError("Rendu nft invalide")
    if not isinstance(wan, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", wan):
        raise LegacyFirewallError("Interface WAN invalide")

    headers = list(re.finditer(r'(?m)^[ \t]*chain input[ \t]*\{[ \t]*$', nft_text))
    if len(headers) != 1:
        raise LegacyFirewallError("Chaîne INPUT absente ou dupliquée")
    tail = nft_text[headers[0].end():]
    end = re.search(r'(?m)^[ \t]*\}[ \t]*$', tail)
    if end is None:
        raise LegacyFirewallError("Fin de chaîne INPUT non vérifiable")
    block = tail[:end.start()]
    if not re.search(r'type filter hook input priority -30;[ \t]*policy accept;', block):
        raise LegacyFirewallError("Politique INPUT historique inconnue")

    pattern = (
        r'(?m)^[ \t]*iifname "' + re.escape(wan) +
        r'"[ \t]+ip daddr[ \t]+(?P<ips>\{[^\r\n{}]+\}|'
        r'(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
        r'[ \t]+drop[ \t]*(?:#[^\r\n]*)?$'
    )
    matching = list(re.finditer(pattern, block))
    if len(matching) != 1:
        raise LegacyFirewallError("INPUT drop historique absent ou dupliqué")
    raw = matching[0].group("ips").strip()
    parts = [part.strip() for part in raw[1:-1].split(",")] if raw.startswith("{") else [raw]
    if not parts or any(not part for part in parts):
        raise LegacyFirewallError("Ensemble IPv4 INPUT vide ou mal formé")
    ips = []
    for item in parts:
        try:
            addr = ipaddress.IPv4Address(item)
        except ipaddress.AddressValueError as exc:
            raise LegacyFirewallError("IPv4 INPUT invalide") from exc
        if not addr.is_global:
            raise LegacyFirewallError("IPv4 non publique dans INPUT")
        ips.append(str(addr))
    if len(ips) != len(set(ips)):
        raise LegacyFirewallError("IPv4 dupliquée dans INPUT")
    return frozenset(ips), matching[0].group(0).strip()


def inject_routed_forward(legacy_nft, *, wan, wg, management_ip,
                          assignments, peers, legacy_nat_mappings):
    """Preview exact routed /32 FORWARD allowances before legacy drops.

    This function does NOT execute the preview. A future verified transaction
    must migrate the /32 WAN alias, NAT config, routes and peer state atomically.
    """
    if not isinstance(legacy_nft, str) or len(legacy_nft) > 1_000_000:
        raise LegacyFirewallError("Rendu nft invalide")
    try:
        rules = routed_rules(
            wan=wan, wg=wg, management_ip=management_ip,
            assignments=assignments, peers=peers,
            legacy_nat_mappings=legacy_nat_mappings,
        )
    except FirewallPreviewError as exc:
        raise LegacyFirewallError(str(exc)) from exc
    if not assignments:
        return legacy_nft

    if legacy_nft.count("table ip cerato_network {") != 1:
        raise LegacyFirewallError("Table nft du contrôleur inconnue")
    if not re.search(r'chain forward[ \t]*\{', legacy_nft):
        raise LegacyFirewallError("Chaîne FORWARD introuvable")
    if not re.search(r'type filter hook forward priority -30;', legacy_nft):
        raise LegacyFirewallError("Priorité FORWARD inattendue")
    if "flush ruleset" in legacy_nft:
        raise LegacyFirewallError("Rendu nft destructif interdit")

    # Block stale DNAT for the exact routed /32, while permitting other IPs
    # to keep their existing legacy NAT mappings.
    for row in assignments:
        address = row["ip"]
        forbidden = (
            r'(?m)iifname "' + re.escape(wan) +
            r'"[ \t]+ip daddr[ \t]+' + re.escape(address) + r'\b.*dnat to'
        )
        if re.search(forbidden, legacy_nft):
            raise LegacyFirewallError("DNAT historique toujours présente pour IPv4 routée")

    incoming = _exact_drop(legacy_nft, wan, wg)
    outgoing = _exact_drop(legacy_nft, wg, wan)
    header = re.search(r'(?m)^[ \t]*chain forward[ \t]*\{', legacy_nft)
    next_chain = re.search(r'(?m)^[ \t]*chain input[ \t]*\{',
                           legacy_nft[header.end():])
    if next_chain is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary = header.end() + next_chain.start()
    if re.search(r'(?m)^[ \t]*chain [a-z]+[ \t]*\{',
                 legacy_nft[header.end():boundary]):
        raise LegacyFirewallError("Chaîne intermédiaire FORWARD inattendue")
    if any(line in legacy_nft for line in
           rules["forward_before_wan_drop"] + rules["forward_before_wg_drop"]):
        raise LegacyFirewallError("Règle routée déjà insérée")
    if (incoming.start() < header.end() or outgoing.start() < header.end()
            or incoming.start() >= boundary or outgoing.start() >= boundary):
        raise LegacyFirewallError("DROP en dehors de FORWARD")
    if incoming.start() >= outgoing.start():
        raise LegacyFirewallError("Ordre FORWARD inattendu")

    protected, original_guard = guarded_public_ips(legacy_nft, wan)
    if any(row["ip"] not in protected for row in assignments):
        raise LegacyFirewallError("IPv4 routée absente de la protection INPUT")

    patches = [
        (outgoing.start(), rules["forward_before_wg_drop"]),
        (incoming.start(), rules["forward_before_wan_drop"]),
    ]
    result = legacy_nft
    for index, new_lines in patches:
        indentation = re.match(r'[ \t]*', result[index:]).group()
        result = (result[:index] +
                  "".join(indentation + line + "\n" for line in new_lines) +
                  result[index:])
    if result == legacy_nft:
        raise LegacyFirewallError("Aucune règle ajoutée")
    if guarded_public_ips(result, wan) != (protected, original_guard):
        raise LegacyFirewallError("Protection INPUT modifiée : rendu refusé")
    return result

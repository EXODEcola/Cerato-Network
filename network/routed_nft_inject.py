"""Pure adapter for adding routed-IPv4 allow rules to legacy Cerato nft output.

It intentionally does not call nftables. It refuses unknown table/chain
structures and never grants access beyond explicitly assigned public /32s.
The existing gateway INPUT drop and existing legacy DNAT/filter behavior
remain untouched.
"""
from __future__ import annotations

import re
try:
    from .routed_firewall import routed_rules, FirewallPreviewError
except ImportError:
    from routed_firewall import routed_rules, FirewallPreviewError


class LegacyFirewallError(ValueError):
    pass


def _exact_drop(text, incoming, outgoing):
    # Only accept the exact two-interface drop shape observed in RISE-1.
    pattern=(r'(?m)^[ \t]*iifname "'+re.escape(incoming)+
             r'"[ \t]+oifname "'+re.escape(outgoing)+
             r'"[ \t]+drop[ \t]*(?:#[^\n]*)?$')
    matches=list(re.finditer(pattern,text))
    if len(matches)!=1:
        raise LegacyFirewallError("DROP FORWARD historique manquant ou dupliqué")
    return matches[0]


def inject_routed_forward(legacy_nft, *, wan, wg, management_ip,
                          assignments, peers, legacy_nat_mappings):
    """Add only exact routed public /32 FORWARD allows before the old drops.

    Invoking this on a config that still contains a per-port DNAT for the
    same public IP is refused. The caller must also migrate state, IPv4 alias,
    WG AllowedIPs and route with independently verified rollback.
    """
    if not isinstance(legacy_nft,str) or len(legacy_nft)>1_000_000:
        raise LegacyFirewallError("nft render must be a bounded UTF-8 text")
    try:
        rules=routed_rules(wan=wan,wg=wg,management_ip=management_ip,
                           assignments=assignments,peers=peers,
                           legacy_nat_mappings=legacy_nat_mappings)
    except FirewallPreviewError as exc:
        raise LegacyFirewallError(str(exc)) from exc
    if not assignments:
        return legacy_nft
    # Reject previously injected or unknown layouts; no broad ruleset flush.
    if legacy_nft.count("table ip cerato_network {")!=1:
        raise LegacyFirewallError("Table nft du contrôleur inconnue")
    if not re.search(r'chain forward[ \t]*\{',legacy_nft):
        raise LegacyFirewallError("Chaîne forward du contrôleur introuvable")
    if not re.search(r'type filter hook forward priority -30;',legacy_nft):
        raise LegacyFirewallError("Priorité de chaîne forward inattendue")
    if any('flush ruleset' in line for line in legacy_nft.splitlines()):
        raise LegacyFirewallError("Rendu nft destructif interdit")
    if re.search(r'(?m)^[ \t]*iifname "'+re.escape(wan)+
                 r'"[ \t]+ip daddr '+r'(?:(?:\d{1,3}\.){3}\d{1,3})'+
                 r'.*dnat to',legacy_nft):
        # Only disallow DNAT to the routed IP, not unrelated active mappings:
        for entry in assignments:
            public=entry["ip"]
            if re.search(r'(?m)iifname "'+re.escape(wan)+
                         r'"[ \t]+ip daddr '+re.escape(public)+r'\b.*dnat to',
                         legacy_nft):
                raise LegacyFirewallError("DNAT encore présente sur la /32 routée")

    incoming=_exact_drop(legacy_nft,wan,wg)
    outgoing=_exact_drop(legacy_nft,wg,wan)
    fwd_match=re.search(r'(?m)^[ \t]*chain forward[ \t]*\{',legacy_nft)
    next_match=re.search(r'(?m)^[ \t]*chain (?:input|postrouting|output|prerouting)[ \t]*\{',
                          legacy_nft[fwd_match.end():])
    if next_match is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary=fwd_match.end()+next_match.start()
    if incoming.start()<fwd_match.end() or outgoing.start()<fwd_match.end() or (
            incoming.start()>=boundary or outgoing.start()>=boundary):
        raise LegacyFirewallError("DROP en dehors de FORWARD")
    if incoming.start()>=outgoing.start():
        raise LegacyFirewallError("Ordre FORWARD inattendu")
    # Existing INPUT drop must remain present so the gateway is not a
    # public endpoint for the routed IP during a staged migration.
    for entry in assignments:
        ip=entry["ip"]
        guard=re.compile(r'(?m)iifname "'+re.escape(wan)+
                         r'"[ \t]+ip daddr '+re.escape(ip)+r'[ \t]+drop\b')
        if len(guard.findall(legacy_nft))!=1:
            raise LegacyFirewallError("INPUT drop historique absent ou dupliqué")

    # Insert from right to left to retain stable positions.
    parts=[
        (outgoing.start(),rules["forward_before_wg_drop"]),
        (incoming.start(),rules["forward_before_wan_drop"]),
    ]
    patched=legacy_nft
    for index, lines in parts:
        indentation=re.match(r'[ \t]*',patched[index:]).group()
        block=''.join(indentation + line + "\n" for line in lines)
        patched=patched[:index]+block+patched[index:]
    if patched==legacy_nft:
        raise LegacyFirewallError("Aucune règle ajoutée")
    return patched

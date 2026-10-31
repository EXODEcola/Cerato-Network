"""Pure adapter for adding routed-IPv4 allow rules to legacy Cerato nft output.

It intentionally does not call nftables. It refuses unknown table/chain
structures and never grants access beyond explicitly assigned public /32s.
The existing gateway INPUT drop and existing legacy DNAT/filter behavior
remain untouched.
"""
from __future__ import annotations

import re
import ipaddress
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


def guarded_public_ips(nft_text, wan):
    """Verify an exact INPUT drop on the gateway WAN, including nft IPv4 sets.

    The live render_nft uses the Cerato IPv4 pool to build an nft literal
    set: ip daddr { 54.37.165.151, ... } drop. A single IP rule is also
    supported. No CIDRs, ranges, wildcard rules, ambiguous chains or
    duplicate guards are accepted. Return the exact original guard line,
    which must remain byte-for-byte unchanged in the routed preview.
    """
    if not isinstance(nft_text,str) or len(nft_text)>1_000_000:
        raise LegacyFirewallError("Rendu nft invalide")
    if not isinstance(wan,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}",wan):
        raise LegacyFirewallError("Interface WAN invalide")
    headers=list(re.finditer(r'(?m)^[ \t]*chain input[ \t]*\{[ \t]*
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
    next_match=re.search(r'(?m)^[ \t]*chain input[ \t]*\{',
                          legacy_nft[fwd_match.end():])
    if next_match is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary=fwd_match.end()+next_match.start()
    if re.search(r'(?m)^[ \t]*chain [a-z]+[ \t]*\{',
                 legacy_nft[fwd_match.end():boundary]):
        raise LegacyFirewallError("Chaîne intermédiaire FORWARD inattendue")
    if any(line in legacy_nft for line in
           rules["forward_before_wan_drop"] + rules["forward_before_wg_drop"]):
        raise LegacyFirewallError("Règle routée déjà insérée")
    if incoming.start()<fwd_match.end() or outgoing.start()<fwd_match.end() or (
            incoming.start()>=boundary or outgoing.start()>=boundary):
        raise LegacyFirewallError("DROP en dehors de FORWARD")
    if incoming.start()>=outgoing.start():
        raise LegacyFirewallError("Ordre FORWARD inattendu")
    # Preserve the original INPUT guard, whether individual IPv4 or a set
    # emitted from the legacy Cerato IP pool. Require the routed IPv4 to be
    # a member of that exact drop, not merely present in an unrelated line.
    protected,original_guard=guarded_public_ips(legacy_nft,wan)
    if any(entry["ip"] not in protected for entry in assignments):
        raise LegacyFirewallError("IPv4 routée absente de la protection INPUT")

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
    if guarded_public_ips(patched,wan)!=(protected,original_guard):
        raise LegacyFirewallError("Protection INPUT modifiée : rendu refusé")
    return patched
,nft_text))
    if len(headers)!=1:
        raise LegacyFirewallError("Chaîne INPUT absente ou dupliquée")
    tail=nft_text[headers[0].end():]
    closing=re.search(r'(?m)^[ \t]*\}[ \t]*
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
    next_match=re.search(r'(?m)^[ \t]*chain input[ \t]*\{',
                          legacy_nft[fwd_match.end():])
    if next_match is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary=fwd_match.end()+next_match.start()
    if re.search(r'(?m)^[ \t]*chain [a-z]+[ \t]*\{',
                 legacy_nft[fwd_match.end():boundary]):
        raise LegacyFirewallError("Chaîne intermédiaire FORWARD inattendue")
    if any(line in legacy_nft for line in
           rules["forward_before_wan_drop"] + rules["forward_before_wg_drop"]):
        raise LegacyFirewallError("Règle routée déjà insérée")
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
,tail)
    if closing is None:
        raise LegacyFirewallError("Fin de chaîne INPUT non vérifiable")
    block=tail[:closing.start()]
    if not re.search(
        r'type filter hook input priority -30;[ \t]*policy accept;',block):
        raise LegacyFirewallError("Priorité INPUT ou politique historique inconnue")
    # The set is literal and parsed as IPv4 addresses, never evaluated.
    pattern=(r'(?m)^[ \t]*iifname "'+re.escape(wan)+
             r'"[ \t]+ip daddr[ \t]+(?P<ips>\{[^\r\n{}]+\}|'
             r'(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
             r'[ \t]+drop[ \t]*(?:#[^\r\n]*)?
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
    next_match=re.search(r'(?m)^[ \t]*chain input[ \t]*\{',
                          legacy_nft[fwd_match.end():])
    if next_match is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary=fwd_match.end()+next_match.start()
    if re.search(r'(?m)^[ \t]*chain [a-z]+[ \t]*\{',
                 legacy_nft[fwd_match.end():boundary]):
        raise LegacyFirewallError("Chaîne intermédiaire FORWARD inattendue")
    if any(line in legacy_nft for line in
           rules["forward_before_wan_drop"] + rules["forward_before_wg_drop"]):
        raise LegacyFirewallError("Règle routée déjà insérée")
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
)
    matched=list(re.finditer(pattern,block))
    if len(matched)!=1:
        raise LegacyFirewallError("INPUT drop historique absent ou dupliqué")
    text=matched[0].group("ips").strip()
    if text.startswith("{"):
        items=[item.strip() for item in text[1:-1].split(",")]
    else:
        items=[text]
    if not items or any(not item for item in items):
        raise LegacyFirewallError("Ensemble INPUT vide ou mal formé")
    parsed=[]
    for item in items:
        try:
            addr=ipaddress.IPv4Address(item)
        except ipaddress.AddressValueError as exc:
            raise LegacyFirewallError("IPv4 INPUT invalide") from exc
        if not addr.is_global:
            raise LegacyFirewallError("INPUT contient une IPv4 non publique")
        parsed.append(str(addr))
    if len(parsed)!=len(set(parsed)):
        raise LegacyFirewallError("IPv4 dupliquée dans INPUT")
    return frozenset(parsed),matched[0].group(0).strip()


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
    next_match=re.search(r'(?m)^[ \t]*chain input[ \t]*\{',
                          legacy_nft[fwd_match.end():])
    if next_match is None:
        raise LegacyFirewallError("Fin de chaîne FORWARD non vérifiable")
    boundary=fwd_match.end()+next_match.start()
    if re.search(r'(?m)^[ \t]*chain [a-z]+[ \t]*\{',
                 legacy_nft[fwd_match.end():boundary]):
        raise LegacyFirewallError("Chaîne intermédiaire FORWARD inattendue")
    if any(line in legacy_nft for line in
           rules["forward_before_wan_drop"] + rules["forward_before_wg_drop"]):
        raise LegacyFirewallError("Règle routée déjà insérée")
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

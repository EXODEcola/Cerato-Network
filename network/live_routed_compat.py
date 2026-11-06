"""Pure adapters for RISE-1's generated WireGuard peers and nftables.

Never invokes ip, wg, nft or any shell command. This module is an offline
compatibility layer, not a privileged migration or persistent cutover agent.
"""
from __future__ import annotations
import ipaddress
import re

try:
    from .routed_nft_inject import inject_routed_forward
except ImportError:
    from routed_nft_inject import inject_routed_forward


class RoutedCompatError(ValueError):
    pass


def public(value):
    try:
        ip=ipaddress.ip_address(value)
    except (ValueError,TypeError) as exc:
        raise RoutedCompatError("IPv4 publique mal formée") from exc
    if ip.version!=4 or not ip.is_global:
        raise RoutedCompatError("IPv4 publique globale requise")
    return str(ip)


def plans(data):
    """Validated routes shared by all rendering functions.

    Fail closed if host management IP is absent, if any legacy NAT overlaps
    a routed /32, or if the routed entry points to an unknown VPN peer.
    """
    if not isinstance(data,dict):
        raise RoutedCompatError("Configuration non conforme")
    routes=data.get("routed_ipv4",[])
    if not isinstance(routes,list) or len(routes)>256:
        raise RoutedCompatError("Allocations routées invalides")
    if not routes:
        return []
    management=public(data.get("management_ipv4"))
    peers=data.get("peers")
    pool=data.get("pool")
    mappings=data.get("mappings")
    if not isinstance(peers,dict) or not isinstance(pool,list) or not isinstance(mappings,list):
        raise RoutedCompatError("Pool ou pairs Cerato incomplets")
    result=[]
    used=set()
    keys=set()
    for entry in routes:
        if not isinstance(entry,dict) or set(entry)!={"ip","peer"}:
            raise RoutedCompatError("Entrée IPv4 routée invalide")
        ip=public(entry["ip"])
        peer=entry["peer"]
        if ip==management or ip not in pool or ip in used:
            raise RoutedCompatError("IPv4 principale, hors pool ou déjà attribuée")
        if not isinstance(peer,str) or peer not in peers:
            raise RoutedCompatError("Pair WireGuard introuvable")
        p=peers[peer]
        if not isinstance(p,dict) or "pubkey" not in p or "ip" not in p:
            raise RoutedCompatError("Clé ou IP du pair absente")
        try:
            vpn=ipaddress.ip_address(p["ip"])
        except (ValueError,TypeError) as exc:
            raise RoutedCompatError("Pair VPN invalide") from exc
        if vpn.version!=4 or not vpn.is_private:
            raise RoutedCompatError("Adresse privée WireGuard requise")
        key=p["pubkey"]
        if not isinstance(key,str) or not key.strip():
            raise RoutedCompatError("Clé publique WireGuard invalide")
        for m in mappings:
            if not isinstance(m,dict) or m.get("public_ip")==ip:
                raise RoutedCompatError("Publication NAT toujours active sur IPv4 routée")
        used.add(ip)
        keys.add(key)
        result.append({"ip":ip,"peer":peer,"vpn":str(vpn),"key":key})
    # Two peers may not use a single cryptokey for different routed IPs.
    by_key={}
    for item in result:
        owner=by_key.setdefault(item["key"],item["peer"])
        if owner!=item["peer"]:
            raise RoutedCompatError("Clé WireGuard attribuée à deux pairs")
    return sorted(result,key=lambda r:int(ipaddress.ip_address(r["ip"])))


def routed_render_nft(raw,data):
    if not isinstance(raw,str):
        raise RoutedCompatError("Rendu nft invalide")
    selected=plans(data)
    if not selected:
        return raw
    return inject_routed_forward(
        raw,wan=data["wan_if"],wg=data["wg_if"],
        management_ip=data["management_ipv4"],
        assignments=[{"ip":x["ip"],"peer":x["peer"]} for x in selected],
        peers=data["peers"],legacy_nat_mappings=data["mappings"])


def routed_extend_wg(original,data):
    """Extend generated AllowedIPs for a peer using its EXISTING public key.

    No private key is read or copied here; only the rendered in-memory text is
    transformed. Unknown or duplicated peer identities and missing AllowedIPs
    fail rather than modifying the wrong peer.
    """
    if not isinstance(original,str) or len(original)>1_000_000:
        raise RoutedCompatError("WG generated text invalid")
    selected=plans(data)
    if not selected:
        return original
    by_key={}
    for row in selected:
        by_key.setdefault(row["key"],[]).append(row)
    blocks=re.split(r"(?m)(?=^\[Peer\]\s*$)",original)
    if len(blocks)<2:
        raise RoutedCompatError("Fichier WireGuard sans sections pair")
    updated=[blocks[0]]
    seen=set()
    for block in blocks[1:]:
        lines=block.splitlines(keepends=True)
        key_lines=[line for line in lines if re.match(r"^\s*PublicKey\s*=",line)]
        if len(key_lines)!=1:
            raise RoutedCompatError("Section pair sans unique clé publique")
        key=key_lines[0].split("=",1)[1].strip()
        if key not in by_key:
            updated.append(block)
            continue
        if key in seen:
            raise RoutedCompatError("Pair WG dupliqué")
        seen.add(key)
        allowed=[i for i,line in enumerate(lines)
                 if re.match(r"^\s*AllowedIPs\s*=",line)]
        if len(allowed)!=1:
            raise RoutedCompatError("Section pair sans unique AllowedIPs")
        index=allowed[0]
        value=lines[index].split("=",1)[1].strip()
        current=[v.strip() for v in value.split(",") if v.strip()]
        try:
            current=[str(ipaddress.ip_network(x,strict=False)) for x in current]
        except ValueError as exc:
            raise RoutedCompatError("AllowedIPs invalide") from exc
        required={r["vpn"]+"/32" for r in by_key[key]}
        if not required.issubset(set(current)):
            raise RoutedCompatError("AllowedIPs VPN historiques absents")
        for row in by_key[key]:
            item=row["ip"]+"/32"
            if item not in current:
                current.append(item)
        newline="\r\n" if lines[index].endswith("\r\n") else "\n"
        match=re.match(r"^(\s*AllowedIPs\s*=\s*)",lines[index])
        if match is None:
            raise RoutedCompatError("Ligne AllowedIPs invalide")
        lines[index]=match.group(1)+", ".join(current)+newline
        updated.append("".join(lines))
    if seen!=set(by_key):
        raise RoutedCompatError("Pair WG assigné introuvable dans le fichier")
    return "".join(updated)

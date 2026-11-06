"""Canonical, read-only status of Additional IPv4 allocations for the live panel.

Source: existing privileged cerato-ipctl status response (pool and
persisted local/routed allocations). Routed IPv4 must NOT be on WAN.
No network operations, secrets, WireGuard keys or config mutations.
Malformed or contradictory sources fail closed.
"""
from __future__ import annotations
import ipaddress
import re

class RoutedUIError(ValueError):
    pass

PEER_RE=re.compile(r"^[a-z][a-z0-9-]{0,39}$")

def _ipv4(value):
    if not isinstance(value,str):
        raise RoutedUIError("Adresse IPv4 invalide")
    try:
        ip=ipaddress.ip_address(value)
    except ValueError as exc:
        raise RoutedUIError("Adresse IPv4 invalide") from exc
    if ip.version!=4 or not ip.is_global:
        raise RoutedUIError("IPv4 publique attendue")
    return str(ip)

def summarize(ipctl_status):
    """Translate trusted ipctl status to safe UI rows and counts."""
    if not isinstance(ipctl_status,dict):
        raise RoutedUIError("État Additional IPv4 absent")
    pool=ipctl_status.get("pool")
    managed=ipctl_status.get("managed")
    if not isinstance(pool,list) or not isinstance(managed,list):
        raise RoutedUIError("Pool ou attributions non remontés")
    if len(pool)>256 or len(managed)>256:
        raise RoutedUIError("Limite du pool dépassée")
    parsed_pool=[_ipv4(p) for p in pool]
    if len(set(parsed_pool))!=len(parsed_pool):
        raise RoutedUIError("Adresse dupliquée dans le pool")
    pool_set=set(parsed_pool)
    main=_ipv4(ipctl_status.get("primary_ipv4"))
    if main in pool_set:
        raise RoutedUIError("IPv4 de gestion retrouvée dans le pool")
    by_ip={}
    for row in managed:
        if not isinstance(row,dict):
            raise RoutedUIError("Entrée Additional IPv4 invalide")
        ip=_ipv4(row.get("ip"))
        if ip in by_ip:
            raise RoutedUIError("IPv4 attribuée plusieurs fois")
        mode=row.get("mode")
        if mode not in ("local-nat","routed-wg"):
            raise RoutedUIError("Mode d'attribution inconnu")
        if mode=="local-nat":
            present=row.get("present")
            if not isinstance(present,bool):
                raise RoutedUIError("Statut interface WAN manquant")
            payload={"ip":ip,"mode":mode,
                     "state":"local" if present else "warning",
                     "label":"Locale sur OVH" if present else "Locale — alias WAN absent",
                     "peer":None,"present_on_wan":present,
                     "assigned":present,"can_remove":False}
        else:
            peer=row.get("peer")
            on_wan=row.get("present_on_wan")
            if not isinstance(peer,str) or not PEER_RE.fullmatch(peer):
                raise RoutedUIError("Machine WireGuard inconnue")
            if not isinstance(on_wan,bool):
                raise RoutedUIError("Statut WAN routé manquant")
            payload={"ip":ip,"mode":mode,"state":"warning" if on_wan else "routed",
                     "label":"Conflit : IPv4 routée encore sur la WAN" if on_wan
                              else "Routée vers une machine",
                     "peer":peer,"present_on_wan":on_wan,
                     "assigned":True,"can_remove":False}
        by_ip[ip]=payload
    if not set(by_ip).issubset(pool_set):
        raise RoutedUIError("Attribution hors du pool Cerato")
    rows=[]
    for ip in sorted(parsed_pool,key=lambda x:int(ipaddress.ip_address(x))):
        if ip in by_ip:
            rows.append(by_ip[ip])
        else:
            rows.append({"ip":ip,"mode":"available","state":"available",
                         "label":"Disponible","peer":None,
                         "present_on_wan":None,"assigned":False,
                         "can_remove":True})
    assigned=sum(bool(row["assigned"]) for row in rows)
    routed=sum(row["mode"]=="routed-wg" for row in rows)
    warnings=sum(row["state"]=="warning" for row in rows)
    mappings=ipctl_status.get("mappings")
    return {"schema":"cerato-ipv4-allocations-v1",
            "total":len(rows),"allocated_count":assigned,
            "routed_count":routed,"available_count":len(rows)-assigned,
            "local_count":sum(row["mode"]=="local-nat" for row in rows),
            "warnings":warnings,
            "entries":rows,
            "nat_publications":mappings if isinstance(mappings,int) and mappings>=0 else None,
            "note":"Une IPv4 routée n'est pas un alias WAN et ne nécessite aucune publication NAT."}

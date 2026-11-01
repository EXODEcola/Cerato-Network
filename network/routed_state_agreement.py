"""Pure agreement contract between live Cerato config and Additional-IP state.

A routed /32 may only be handed to the existing nft/WG renderer after
both authoritative files agree. This module never reads or writes files,
inspects private keys, or changes addresses, routes, WireGuard or nftables.
The privileged gateway transaction must update both files with independent
recovery and verify that no stale NAT rule can be regenerated.
"""
from __future__ import annotations
from copy import deepcopy
import ipaddress

try:
    from .live_routed_compat import plans, RoutedCompatError
except ImportError:
    from live_routed_compat import plans, RoutedCompatError


class StateAgreementError(ValueError):
    pass


def _ip(text):
    try:
        address=ipaddress.ip_address(text)
    except (TypeError,ValueError) as exc:
        raise StateAgreementError("IPv4 invalide") from exc
    if address.version!=4 or not address.is_global:
        raise StateAgreementError("IPv4 globale requise")
    return str(address)


def _routes(data,*,include_wan):
    if not isinstance(data,list) or len(data)>256:
        raise StateAgreementError("Liste routée invalide")
    result={}
    for row in data:
        keys={"ip","peer","wan"} if include_wan else {"ip","peer"}
        if not isinstance(row,dict) or set(row)!=keys:
            raise StateAgreementError("Entrée de routage invalide")
        ip=_ip(row["ip"])
        peer=row["peer"]
        if not isinstance(peer,str) or not peer:
            raise StateAgreementError("Pair de routage invalide")
        if ip in result:
            raise StateAgreementError("IPv4 routée attribuée deux fois")
        if include_wan and (not isinstance(row["wan"],str) or not row["wan"]):
            raise StateAgreementError("WAN routée inconnue")
        result[ip]=(peer,row.get("wan"))
    return result


def agreed_renderer_config(controller,managed,*,observed_primary_ip):
    """Return a new in-memory config only when config and state agree.

    This is *not* a commit function, API handler or rollback mechanism.
    """
    if not isinstance(controller,dict) or not isinstance(managed,dict):
        raise StateAgreementError("Fichiers d'état invalides")
    if managed.get("schema")!=1:
        raise StateAgreementError("Schéma d'état non reconnu")
    primary=_ip(observed_primary_ip)
    declared=_routes(controller.get("routed_ipv4",[]),include_wan=False)
    persisted=_routes(managed.get("routed_ipv4",[]),include_wan=True)
    if set(declared)!=set(persisted):
        raise StateAgreementError("État des IPv4 routées différent du contrôleur")
    if primary in declared:
        raise StateAgreementError("IPv4 principale ne peut pas être routée")
    wan=controller.get("wan_if")
    if not isinstance(wan,str) or not wan:
        raise StateAgreementError("WAN principale manquante")
    for ip,entry in declared.items():
        if entry[0]!=persisted[ip][0] or persisted[ip][1]!=wan:
            raise StateAgreementError("Pair ou WAN différent entre les états")
    local=managed.get("local_ipv4")
    if not isinstance(local,list):
        raise StateAgreementError("Liste des IPv4 locales absente")
    local_ips=set()
    for row in local:
        if not isinstance(row,dict) or "ip" not in row:
            raise StateAgreementError("Entrée locale mal formée")
        ip=_ip(row["ip"])
        if ip in local_ips:
            raise StateAgreementError("IPv4 locale dupliquée")
        local_ips.add(ip)
    if local_ips.intersection(declared):
        raise StateAgreementError("Adresse routée encore gérée comme alias WAN")
    # The actual controller derives its trusted WAN primary IP from the
    # kernel route. It must never accept this value from a Web form.
    if "management_ipv4" in controller and controller["management_ipv4"]!=primary:
        raise StateAgreementError("IPv4 de gestion différente de la route système")
    result=deepcopy(controller)
    result["management_ipv4"]=primary
    if declared:
        try:
            plans(result)
        except RoutedCompatError as exc:
            raise StateAgreementError("Configuration routed-WG invalide") from exc
    return result

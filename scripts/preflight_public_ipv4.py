#!/usr/bin/env python3
"""Diagnostic en lecture seule du trajet Additional IPv4 -> WireGuard.

Aucune commande d'application réseau, aucune clé ou configuration WireGuard
privée n'est affichée. Cet outil ne vérifie PAS à lui seul l'acheminement OVH,
un pare-feu amont ou une connexion de bout en bout.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import time


IFACE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("IPv4 invalide") from exc
    if address.version != 4 or not address.is_global:
        raise argparse.ArgumentTypeError("Une IPv4 publique est requise")
    return str(address)


def private_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("IPv4 de tunnel invalide") from exc
    if address.version != 4 or not address.is_private:
        raise argparse.ArgumentTypeError("Une IPv4 privée est requise")
    return str(address)


def interface(value):
    if not IFACE.fullmatch(value):
        raise argparse.ArgumentTypeError("Nom d'interface invalide")
    return value


def command(argv):
    """Lecture système uniquement, sans shell et sans remontée de stderr."""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Commande de diagnostic indisponible") from exc
    if completed.returncode:
        raise RuntimeError("Commande de diagnostic refusée")
    return completed.stdout


def address_set(read, device):
    result = json.loads(read(["ip", "-j", "-4", "addr", "show", "dev", device]))
    return {item.get("local") for nic in result for item in nic.get("addr_info", [])
            if item.get("family") == "inet"}


def route_device(read, destination, source=None):
    argv = ["ip", "-j", "-4", "route", "get", destination]
    if source:
        argv.extend(["from", source])
    routes = json.loads(read(argv))
    return routes[0].get("dev") if routes else None


def wg_peer_state(read, tunnel, peer_ip):
    """Ne renvoie jamais les clés publiques des pairs."""
    wanted = ipaddress.ip_address(peer_ip)
    mapping = {}
    for line in read(["wg", "show", tunnel, "allowed-ips"]).splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        for cidr in parts[1:]:
            try:
                subnet = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if wanted in subnet:
                mapping[parts[0]] = subnet.prefixlen
                break
    if not mapping:
        return {"configured": False, "handshake_recent": False,
                "specific_route": False}
    newest = 0
    for line in read(["wg", "show", tunnel, "latest-handshakes"]).splitlines():
        parts = line.split()
        if len(parts) != 2 or parts[0] not in mapping:
            continue
        if parts[1].isdigit():
            newest = max(newest, int(parts[1]))
    return {
        "configured": True,
        "specific_route": any(length == 32 for length in mapping.values()),
        "handshake_recent": newest > 0 and 0 <= time.time() - newest < 300,
    }


def check(read, role, public_ip, tunnel, peer_ip, wan, mode, port):
    findings = []

    def report(code, status, message):
        findings.append({"code": code, "status": status, "message": message})

    def probe(code, fn, on_success):
        try:
            on_success(fn())
        except (RuntimeError, ValueError, KeyError, IndexError, TypeError,
                json.JSONDecodeError):
            report(code, "unknown", "Impossible de vérifier ce point en lecture seule")

    probe("wg_interface",
          lambda: read(["ip", "link", "show", "dev", tunnel]),
          lambda _: report("wg_interface", "ok", "Interface tunnel présente"))

    if role == "gateway":
        probe("wan_address", lambda: public_ip in address_set(read, wan),
              lambda present: report(
                  "wan_address",
                  "ok" if present == (mode == "local-nat") else "attention",
                  ("IPv4 présente sur la WAN (mode NAT local)" if present else
                   "IPv4 absente de la WAN : nécessaire à confirmer côté OVH")
                  if mode == "local-nat" else
                  ("IPv4 encore portée localement par la passerelle ; "
                   "risque de conflit avec le routage /32 vers le Dell"
                   if present else "IPv4 non portée localement par la WAN")))

        probe("forwarding",
              lambda: read(["sysctl", "-n", "net.ipv4.ip_forward"]).strip(),
              lambda value: report(
                  "forwarding", "ok" if value == "1" else "attention",
                  "Forwarding IPv4 activé" if value == "1" else
                  "Forwarding IPv4 non confirmé/à activer après revue"))

        probe("peer_route", lambda: route_device(read, peer_ip),
              lambda dev: report("peer_route",
                                 "ok" if dev == tunnel else "attention",
                                 "Route vers le Dell via WireGuard" if dev == tunnel
                                 else "Route vers le Dell non dirigée vers WireGuard"))

        probe("peer_handshake", lambda: wg_peer_state(read, tunnel, peer_ip),
              lambda state: report("peer_handshake",
                                   "ok" if state["handshake_recent"] and
                                   state["specific_route"] else "attention",
                                   "Pair WireGuard et handshake récents" if
                                   state["handshake_recent"] and state["specific_route"]
                                   else "AllowedIPs ou handshake du Dell à examiner"))

        if mode == "routed-wg":
            probe("public_route", lambda: route_device(read, public_ip),
                  lambda dev: report("public_route",
                                     "ok" if dev == tunnel else "attention",
                                     "Route de l'IPv4 /32 vers WireGuard" if dev == tunnel
                                     else "L'IPv4 publique n'est pas routée vers WireGuard"))
        else:
            def nat_status(rules):
                lines = [line for line in rules.splitlines()
                         if public_ip in line and "dnat" in line.lower()]
                exact = any(re.search(r"(?<!\d)" + str(port) + r"(?!\d)", line)
                            and peer_ip in line for line in lines)
                report("nat_rule", "ok" if exact else "attention",
                       "Règle DNAT correspondante détectée dans nftables" if exact
                       else "Règle DNAT exacte non détectée dans nftables")
            probe("nat_rule", lambda: read(["nft", "-a", "list", "ruleset"]),
                  nat_status)
    else:
        probe("peer_tunnel_ip", lambda: peer_ip in address_set(read, tunnel),
              lambda present: report("peer_tunnel_ip",
                                     "ok" if present else "attention",
                                     "IPv4 WireGuard du Dell présente" if present else
                                     "IPv4 WireGuard du Dell absente"))
        if mode == "routed-wg":
            probe("public_on_peer",
                  lambda: public_ip in address_set(read, tunnel),
                  lambda present: report("public_on_peer",
                                         "ok" if present else "attention",
                                         "IPv4 publique /32 présente sur WireGuard" if present
                                         else "IPv4 publique non attribuée au Dell"))
            probe("source_route",
                  lambda: route_device(read, "1.1.1.1", public_ip),
                  lambda dev: report("source_route",
                                     "ok" if dev == tunnel else "attention",
                                     "Retour depuis l'IPv4 publique via WireGuard" if
                                     dev == tunnel else
                                     "La route retour depuis l'IPv4 publique évite WireGuard"))
        probe("listener", lambda: read(["ss", "-H", "-ltn", "sport", "=",
                                        ":" + str(port)]),
              lambda output: report(
                  "listener", "ok" if output.strip() else "attention",
                  "Service TCP en écoute sur le port local" if output.strip()
                  else "Aucun service TCP en écoute sur ce port local"))

    return {
        "role": role, "mode_cible": mode, "checks": findings,
        "limitation": (
            "Ce diagnostic ne prouve pas l'arrivée des paquets depuis Internet, "
            "le filtrage OVH, la chaîne FORWARD, les règles firewall du Dell "
            "ni l'aller-retour réel. Faire ensuite des captures et un test externe."
        ),
        "modifications": False,
    }


def main():
    parser = argparse.ArgumentParser(description="Préflight IPv4 publique / WireGuard (lecture seule)")
    parser.add_argument("--role", choices=["gateway", "peer"], required=True)
    parser.add_argument("--public-ip", type=public_ipv4, required=True)
    parser.add_argument("--tunnel", type=interface, default="wg-cerato")
    parser.add_argument("--peer-ip", type=private_ipv4, required=True)
    parser.add_argument("--wan", type=interface)
    parser.add_argument("--mode", choices=["local-nat", "routed-wg"], default="routed-wg")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.role == "gateway" and not args.wan:
        parser.error("--wan est obligatoire pour la passerelle")
    if not 1 <= args.port <= 65535:
        parser.error("Port hors limites")
    result = check(command, args.role, args.public_ip, args.tunnel,
                   args.peer_ip, args.wan, args.mode, args.port)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    print("Cerato Network — préflight IPv4 (lecture seule)")
    print("Rôle :", result["role"], "| Cible :", result["mode_cible"])
    for item in result["checks"]:
        print(" -", item["status"].upper(), item["code"], ":", item["message"])
    print("Limite :", result["limitation"])


if __name__ == "__main__":
    main()

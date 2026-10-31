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



def source_policy_table(read, source):
    """Return the table of an exact IPv4 'from source' rule, never the full list."""
    source = str(ipaddress.ip_address(source))
    for line in read(["ip", "-4", "rule", "show"]).splitlines():
        match = re.match(
            r"^\s*\d+:\s+from\s+" + re.escape(source) +
            r"(?:/32)?\s+lookup\s+([a-zA-Z0-9_-]+)(?:\s|$)",
            line,
        )
        if match:
            return match.group(1)
    return None


def rp_filter_mode(read, tunnel):
    """Read both global and tunnel reverse-path filters, without writing sysctl."""
    all_mode = int(read(["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]).strip())
    tunnel_mode = int(read([
        "sysctl", "-n", "net.ipv4.conf." + tunnel + ".rp_filter"
    ]).strip())
    if any(value not in (0, 1, 2) for value in (all_mode, tunnel_mode)):
        raise ValueError("Invalid rp_filter")
    # Linux uses max(conf/all, conf/interface) for the effective check.
    return {"all": all_mode, "tunnel": tunnel_mode, "effective": max(all_mode, tunnel_mode)}


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
        probe("vpn_source_policy", lambda: source_policy_table(read, peer_ip),
              lambda table: report(
                  "vpn_source_policy",
                  "ok" if table is not None else "attention",
                  ("Règle source VPN présente vers table " + table) if table
                  else "Aucune règle 'from IPv4 VPN' explicite détectée"))

        probe("rp_filter", lambda: rp_filter_mode(read, tunnel),
              lambda modes: report(
                  "rp_filter",
                  "attention" if modes["effective"] == 1 else "ok",
                  "Filtrage retour strict (1) : vérifier le trafic asymétrique"
                  if modes["effective"] == 1 else
                  ("Filtrage retour souple (2)" if modes["effective"] == 2
                   else "Filtrage retour désactivé (0) : firewall à vérifier")))

        if mode == "local-nat":
            # With a pure DNAT (no source NAT on the gateway), the Dell receives
            # the real external client address. Replies must then use the WG
            # tunnel; a LAN default route would produce asymmetric traffic.
            # This is only a warning: gateway-side SNAT may change the path.
            probe("nat_return_route",
                  lambda: route_device(read, "1.1.1.1", peer_ip),
                  lambda dev: report(
                      "nat_return_route",
                      "ok" if dev == tunnel else "attention",
                      "Réponse source VPN susceptible de passer par WireGuard"
                      if dev == tunnel else
                      "Réponse source VPN envoyée hors WireGuard : risque "
                      "d'asymétrie sans SNAT sur la passerelle"))
        if mode == "routed-wg":
            probe("public_source_policy",
                  lambda: source_policy_table(read, public_ip),
                  lambda table: report(
                      "public_source_policy",
                      "ok" if table is not None else "attention",
                      ("Règle source IPv4 publique présente vers table " + table)
                      if table else
                      "Aucune règle de routage source pour l'IPv4 publique"))
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

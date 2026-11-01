#!/usr/bin/env python3
"""Read-only diagnosis of the *actual* OVH NAT/forward kernel configuration.

No mutation, no firewall dumps, no WireGuard keys and no IP address reassignment.
Real packet loss still requires a synchronized capture.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import subprocess

TARGET="54.37.165.151"
PEER="10.77.0.2"
WAN="enp1s0f0"
WG="wg-cerato"
PORT=8080


class DiagnosticError(ValueError):
    pass


def run(argv):
    allowed={"nft","ip","sysctl"}
    if not argv or argv[0] not in allowed:
        raise DiagnosticError("Commande de lecture non autorisée")
    try:
        proc=subprocess.run(argv,text=True,capture_output=True,timeout=8,
                            check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise DiagnosticError("Lecture système indisponible") from exc
    if proc.returncode:
        raise DiagnosticError("Lecture système refusée")
    return proc.stdout


def walk(obj):
    if isinstance(obj,dict):
        yield obj
        for item in obj.values():
            yield from walk(item)
    elif isinstance(obj,list):
        for item in obj:
            yield from walk(item)


def match_literal(rule,field,value):
    """Require an nft equality right-hand-side for the exact field/value."""
    for node in walk(rule):
        match=node.get("match")
        if not isinstance(match,dict) or match.get("op")!="==":
            continue
        left=match.get("left")
        right=match.get("right")
        if (isinstance(left,dict) and
                left.get("payload")=={"protocol":field[0],"field":field[1]}
                and right==value):
            return True
    return False


def nat_rule(rule):
    if not match_literal(rule,("ip","daddr"),TARGET):
        return False
    if not match_literal(rule,("tcp","dport"),PORT):
        return False
    for value in walk(rule):
        dest=value.get("dnat")
        if isinstance(dest,dict) and dest.get("addr")==PEER and (
                dest.get("port")==PORT or dest.get("port") is None):
            return True
    return False


def chains_and_rules(raw):
    try:
        rows=json.loads(raw)["nftables"]
    except (ValueError,TypeError,KeyError) as exc:
        raise DiagnosticError("Format nft JSON incorrect") from exc
    if not isinstance(rows,list):
        raise DiagnosticError("Éléments nft non conformes")
    chains={}
    rules={}
    for item in rows:
        if not isinstance(item,dict):
            continue
        val=item.get("chain")
        if not isinstance(val,dict) or val.get("table")!="cerato_network" or val.get("family")!="ip":
            continue
        if val.get("name") in chains:
            raise DiagnosticError("Chaîne Cerato dupliquée")
        chains[val.get("name")]=val
    for item in rows:
        if not isinstance(item,dict):
            continue
        val=item.get("rule")
        if not isinstance(val,dict) or val.get("table")!="cerato_network" or val.get("family")!="ip":
            continue
        name=val.get("chain")
        rules.setdefault(name,[]).append(val)
    prerouting=chains.get("prerouting",{})
    forward=chains.get("forward",{})
    nat=[r for r in rules.get("prerouting",[]) if nat_rule(r)]
    def forward_rule_summary(rule):
        expr=rule.get("expr",[])
        return {
            "accept":any("accept" in node for node in walk(expr)),
            "drop":any("drop" in node for node in walk(expr)),
            "ct_dnat":any(isinstance(node.get("ct"),dict) and
                          node["ct"].get("key")=="status"
                          for node in walk(expr)),
            "iif_wan":any(isinstance(node.get("match"),dict) and
                          WAN in str(node["match"].get("right"))
                          for node in walk(expr)),
            "oif_wg":any(isinstance(node.get("match"),dict) and
                         WG in str(node["match"].get("right"))
                         for node in walk(expr)),
        }
    return {
        "prerouting_nat_hook":prerouting.get("hook")=="prerouting"
                               and prerouting.get("type")=="nat",
        "nat_target_rule_count":len(nat),
        "forward_hook":forward.get("hook")=="forward",
        "forward_rule_order":[forward_rule_summary(x) for x in rules.get("forward",[])],
    }


def ip_devs(raw):
    try:
        rows=json.loads(raw)
        if not isinstance(rows,list):
            raise ValueError("not a list")
    except (ValueError,TypeError):
        return None
    return {row.get("dev") for row in rows if isinstance(row,dict)}


def alias_present(raw):
    try:
        rows=json.loads(raw)
        return any(entry.get("local")==TARGET and entry.get("prefixlen")==32
                   for row in rows for entry in row.get("addr_info",[]))
    except (ValueError,TypeError,KeyError,AttributeError):
        return None


def inspect(read):
    table=chains_and_rules(read(["nft","-j","list","table","ip","cerato_network"]))
    devs=ip_devs(read(["ip","-j","-4","route","get",PEER]))
    wan=alias_present(read(["ip","-j","-4","address","show","dev",WAN]))
    forward=read(["sysctl","-n","net.ipv4.ip_forward"]).strip()
    if forward not in ("0","1"):
        forward=None
    return {
        "format":"cerato-actual-nat-8080-runtime-v1",
        "target":TARGET,
        "nft":table,
        "wan_alias_present":wan,
        "ipv4_forward_enabled":None if forward is None else forward=="1",
        "route_to_dell_uses_wg":None if devs is None else WG in devs,
        "tcp_8080_configured_in_kernel":(
            table["prerouting_nat_hook"] and table["nat_target_rule_count"]==1),
        "configuration_modified":False,
        "network_modified":False,
        "note":"Configured rules do not prove matching packets; inspect concurrent captures on WAN and WG.",
    }


def main():
    p=argparse.ArgumentParser(description="Actual OVH NAT 8080 kernel checks (read-only)")
    p.parse_args()
    try:
        result=inspect(run)
    except DiagnosticError as exc:
        p.error(str(exc))
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Read-only nftables packet-path inventory for an OVH->WireGuard public /32.

This tool does not trace packets, execute a migration, modify rules, or print
the ruleset (which may contain private addresses). It identifies other
netfilter base chains that can DROP packets after a Cerato ACCEPT. A positive
finding is not proof of packet loss; a live, timed packet capture is needed.
"""
from __future__ import annotations

import argparse
import json
import subprocess


class InventoryError(ValueError):
    pass


def read_nft():
    try:
        proc=subprocess.run(["nft","-j","list","ruleset"],capture_output=True,
                            text=True,timeout=10,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise InventoryError("nftables est indisponible") from exc
    if proc.returncode:
        raise InventoryError("Lecture nftables refusée")
    return proc.stdout


def verdicts(expr):
    """Count terminal rule expressions without exposing source expressions."""
    if not isinstance(expr,list):
        return {"drop":0,"reject":0,"accept":0}
    totals={"drop":0,"reject":0,"accept":0}
    def visit(value):
        if isinstance(value,dict):
            for key,val in value.items():
                if key in ("accept","drop","reject") and (
                        val is None or isinstance(val,dict)):
                    totals[key]+=1
                visit(val)
        elif isinstance(value,list):
            for item in value:visit(item)
    visit(expr)
    return totals


def inventory(raw,role):
    if role not in ("gateway","peer"):
        raise InventoryError("Rôle inconnu")
    try:
        data=json.loads(raw)
    except (ValueError,TypeError) as exc:
        raise InventoryError("Sortie nft JSON invalide") from exc
    if not isinstance(data,dict) or not isinstance(data.get("nftables"),list):
        raise InventoryError("Format nftables inconnu")
    base={}
    seen=set()
    for obj in data["nftables"]:
        if not isinstance(obj,dict): continue
        chain=obj.get("chain")
        if not isinstance(chain,dict): continue
        if chain.get("hook") not in ("forward","input","prerouting","postrouting","ingress"):
            continue
        family=chain.get("family")
        table=chain.get("table")
        name=chain.get("name")
        if not all(isinstance(x,str) and x for x in (family,table,name)):
            raise InventoryError("Métadonnées de chaîne inconnues")
        key=(family,table,name)
        if key in seen:
            raise InventoryError("Chaîne de base dupliquée")
        seen.add(key)
        priority=chain.get("prio")
        if isinstance(priority,int):
            priority_display=priority
        elif isinstance(priority,str) and len(priority)<40:
            priority_display=priority
        else:
            priority_display="unknown"
        policy=chain.get("policy")
        if policy not in ("accept","drop"):
            policy="unknown"
        base[key]={
            "family":family,"table":table,"chain":name,
            "hook":chain["hook"],"priority":priority_display,
            "policy":policy,"rules":0,"drop_rules":0,
            "reject_rules":0,"accept_rules":0,
        }
    for obj in data["nftables"]:
        if not isinstance(obj,dict): continue
        rule=obj.get("rule")
        if not isinstance(rule,dict): continue
        key=(rule.get("family"),rule.get("table"),rule.get("chain"))
        if key not in base: continue
        counts=verdicts(rule.get("expr"))
        base[key]["rules"]+=1
        for category in counts:
            base[key][category+"_rules"]+=counts[category]
    relevant_hooks={"forward"} if role=="gateway" else {"input"}
    relevant=[
        item for item in base.values()
        if item["hook"] in relevant_hooks and item["family"] in ("ip","inet")
    ]
    relevant.sort(key=lambda v:(v["hook"],str(v["priority"]),v["family"],
                                v["table"],v["chain"]))
    other_base_chain_risk=[
        entry["table"]+"/"+entry["chain"]
        for entry in relevant
        if (entry["table"],entry["chain"])!=(
            ("cerato_network","forward") if role=="gateway"
            else ("cerato_peer_public","input"))
        and (entry["policy"]=="drop" or entry["drop_rules"]>0 or
             entry["reject_rules"]>0 or entry["policy"]=="unknown")
    ]
    return {
        "format":"cerato-nft-path-inventory-v1",
        "role":role,
        "review_hooks":sorted(relevant_hooks),
        "chains":relevant,
        "other_base_chains_with_possible_drop":other_base_chain_risk,
        "critical_fact":"ACCEPT in one base chain does not override DROP in another base chain",
        "risk_is_proven_packet_loss":False,
        "requires_capture_during_active_routing":True,
        "network_modified":False,
        "ready_to_activate":False,
    }


def main():
    p=argparse.ArgumentParser(description="Read-only nftables path inventory")
    p.add_argument("--role",choices=["gateway","peer"],required=True)
    args=p.parse_args()
    try:
        result=inventory(read_nft(),args.role)
    except InventoryError as exc:
        p.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Read-only follow-up: recursively inspect nftables chain jumps/gotos.

Only prints chain names, hook, counts and whether a reachable verdict can
reject/drop traffic. It never prints IP addresses, matching conditions,
SSH/WireGuard keys or raw nftables rules, and never writes to the host.
Counts are POTENTIAL, not proof of a matching rule or dropped packet.
"""
from __future__ import annotations

import argparse
import json
import subprocess


class InspectionError(ValueError):
    pass


def _read():
    try:
        r=subprocess.run(["nft","-j","list","ruleset"],
                         capture_output=True,text=True,timeout=10,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise InspectionError("Lecture nftables indisponible") from exc
    if r.returncode:
        raise InspectionError("Permission nftables insuffisante")
    return r.stdout


def _scan(expr):
    result={"drop":0,"reject":0,"accept":0,"jumps":set(),"dynamic":False}
    def walk(value):
        if isinstance(value,list):
            for item in value:
                walk(item)
        elif isinstance(value,dict):
            for key,item in value.items():
                if key in ("drop","reject","accept") and (
                        item is None or isinstance(item,dict)):
                    result[key]+=1
                elif key in ("jump","goto"):
                    if isinstance(item,dict) and isinstance(item.get("target"),str):
                        result["jumps"].add(item["target"])
                    elif isinstance(item,str):
                        result["jumps"].add(item)
                    else:
                        result["dynamic"]=True
                elif key in ("vmap","dynset","verdict_map"):
                    result["dynamic"]=True
                walk(item)
    walk(expr)
    return result


def inspect(raw, role):
    if role not in ("gateway","peer"):
        raise InspectionError("Rôle invalide")
    try:
        obj=json.loads(raw)
        sequence=obj["nftables"]
    except (ValueError,TypeError,KeyError) as exc:
        raise InspectionError("Fichier nftables illisible") from exc
    if not isinstance(sequence,list):
        raise InspectionError("Données nftables incorrectes")
    chains={}
    rules={}
    for item in sequence:
        if not isinstance(item,dict) or not isinstance(item.get("chain"),dict):
            continue
        row=item["chain"]
        key=(row.get("family"),row.get("table"),row.get("name"))
        if not all(isinstance(p,str) and p for p in key):
            raise InspectionError("Chaîne mal formée")
        if key in chains:
            raise InspectionError("Chaîne nftables déclarée plusieurs fois")
        chains[key]=row
        rules[key]=[]
    for item in sequence:
        if not isinstance(item,dict) or not isinstance(item.get("rule"),dict):
            continue
        row=item["rule"]
        key=(row.get("family"),row.get("table"),row.get("chain"))
        if key not in chains:
            raise InspectionError("Règle d'une chaîne inconnue")
        rules[key].append(_scan(row.get("expr")))
    hook="forward" if role=="gateway" else "input"
    results=[]
    for key,row in chains.items():
        if row.get("hook")!=hook or key[0] not in ("ip","inet"):
            continue
        visited=set()
        reachable={"drop":0,"reject":0,"accept":0}
        missing=set()
        dynamic=False
        edges=0
        def follow(current):
            nonlocal dynamic,edges
            if current in visited:
                return
            visited.add(current)
            if len(visited)>128:
                raise InspectionError("Trop de chaînes liées")
            for info in rules[current]:
                for name in ("drop","reject","accept"):
                    reachable[name]+=info[name]
                dynamic|=info["dynamic"]
                for target in info["jumps"]:
                    edges+=1
                    next_key=(current[0],current[1],target)
                    if next_key not in chains:
                        missing.add(target)
                        dynamic=True
                    else:
                        follow(next_key)
        follow(key)
        results.append({
            "base_chain":"/".join(key),
            "priority":row.get("prio","unknown"),
            "policy":row.get("policy","unknown"),
            "immediate_rule_count":len(rules[key]),
            "reachable_chain_names":sorted(x[2] for x in visited),
            "jump_or_goto_links":edges,
            "reachable_drop_rules":reachable["drop"],
            "reachable_reject_rules":reachable["reject"],
            "reachable_accept_rules":reachable["accept"],
            "unresolved_targets":sorted(missing),
            "dynamic_verdicts_possible":dynamic,
            "potential_drop_in_reachable_chains":(
                bool(reachable["drop"] or reachable["reject"] or
                     row.get("policy")=="drop" or dynamic)),
        })
    results.sort(key=lambda x:x["base_chain"])
    return {
        "format":"cerato-nft-recursive-branches-v1",
        "role":role,
        "hook":hook,
        "chains":results,
        "network_modified":False,
        "drop_proven":False,
        "ready_to_activate":False,
        "interpretation":"Reachability is structural only; counters and packet captures are required during a trial.",
    }


def main():
    p=argparse.ArgumentParser(description="Inspect nft chain links (read only)")
    p.add_argument("--role",choices=["gateway","peer"],required=True)
    a=p.parse_args()
    try:
        result=inspect(_read(),a.role)
    except InspectionError as exc:
        p.error(str(exc))
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

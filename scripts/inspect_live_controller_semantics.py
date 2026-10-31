#!/usr/bin/env python3
"""Live RISE-1 controller AST semantics, no secret values and no live changes.

The report deliberately omits source, string literals, command arguments,
public keys, token values and config values. Only known function identifiers
and structural boolean facts are returned.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

CONTROLLER="/usr/local/sbin/ceratoctl"
BACKEND="/opt/cerato-network/backend/server.py"
KNOWN={"render_nft","rewrite_wg_peers","apply","save","main",
       "netstate","additional_ipctl"}
ALLOWED_KEYS={"wan_if","wg_if","pool","mappings","peers","public_ip",
              "peer","ip","pubkey","private_ip","target_port","public_port",
              "proto","tunnel_cidr","routed_ipv4","local_ipv4","mode",
              "nft","wireguard","route_table"}
ALLOWED_CALLS={"run","save","apply","render_nft","rewrite_wg_peers",
               "systemctl","subprocess.run","subprocess.check_call",
               "subprocess.check_output","json.dumps","json.loads",
               "Path.write_text","os.replace","open","ip4","read_config"}
MARKERS={"nftables":("nft","ruleset","prerouting","forward","dnat"),
         "wireguard":("wg-cerato","wg set","allowed-ips","wg syncconf"),
         "persistence":("config.json","os.replace","write_text","save"),
         "iproute":("ip -4","ip route","ip addr","ip rule")}
IDENT=re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")


def named_call(node):
    if isinstance(node,ast.Name):
        return node.id
    if isinstance(node,ast.Attribute):
        prefix=named_call(node.value)
        return prefix+"."+node.attr if prefix else node.attr
    return ""


def profile_node(node):
    args=[x.arg for x in node.args.posonlyargs+node.args.args+
          node.args.kwonlyargs if IDENT.fullmatch(x.arg)]
    calls=set()
    keys=set()
    raw_markers=set()
    nodes=list(ast.walk(node))
    for child in nodes:
        if isinstance(child,ast.Call):
            name=named_call(child.func)
            if name in ALLOWED_CALLS:
                calls.add(name)
        if isinstance(child,ast.Subscript) and isinstance(child.slice,ast.Constant):
            key=child.slice.value
            if isinstance(key,str) and key in ALLOWED_KEYS:
                keys.add(key)
        if isinstance(child,ast.Constant) and isinstance(child.value,str):
            val=child.value.lower()
            for group, snippets in MARKERS.items():
                if any(s in val for s in snippets):
                    raw_markers.add(group)
        if isinstance(child,ast.JoinedStr):
            for part in child.values:
                if isinstance(part,ast.Constant) and isinstance(part.value,str):
                    val=part.value.lower()
                    for group,snippets in MARKERS.items():
                        if any(s in val for s in snippets):
                            raw_markers.add(group)
    return {
        "function":node.name,"parameters":args,
        "calls":sorted(calls), "config_keys_referenced":sorted(keys),
        "operation_classes":sorted(raw_markers),
        "for_loops":sum(isinstance(v,(ast.For,ast.AsyncFor)) for v in nodes),
        "conditional_branches":sum(isinstance(v,(ast.If,ast.IfExp)) for v in nodes),
        "return_count":sum(isinstance(v,ast.Return) for v in nodes)
    }


def examine(path, expected_sha):
    if str(path) not in (CONTROLLER,BACKEND):
        return {"blocked":"untrusted_path"}
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>150000:
        return {"blocked":"missing_or_untrusted_source"}
    raw=p.read_bytes()
    sha=hashlib.sha256(raw).hexdigest()
    report={"sha256":sha,"sha_matches_expected":sha==expected_sha,
            "source_size_bytes":len(raw),"functions":[]}
    if sha!=expected_sha:
        report["blocked"]="source_version_changed"
        return report
    try:
        tree=ast.parse(raw.decode("utf-8"))
    except (SyntaxError,UnicodeError,ValueError):
        report["blocked"]="not_python"
        return report
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in KNOWN:
            report["functions"].append(profile_node(node))
        if isinstance(node,ast.ClassDef):
            for child in node.body:
                if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef)) and child.name in {"do_GET","do_POST"}:
                    report["functions"].append(profile_node(child))
    report["functions"].sort(key=lambda f:f["function"])
    return report


def main():
    parser=argparse.ArgumentParser(description="Cerato Network AST safe profile (readonly)")
    parser.add_argument("--controller-sha",required=True)
    parser.add_argument("--backend-sha",required=True)
    args=parser.parse_args()
    if not re.fullmatch("[a-f0-9]{64}",args.controller_sha) or not re.fullmatch("[a-f0-9]{64}",args.backend_sha):
        parser.error("Empreintes SHA256 incorrectes")
    print(json.dumps({"schema":"cerato-live-controller-ast-v1",
       "modified":False,"secrets_included":False,
       "controller":examine(CONTROLLER,args.controller_sha),
       "backend":examine(BACKEND,args.backend_sha)},indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Read-only structural inventory of the real Cerato RISE-1 network engine.

Never outputs source lines, literal values, environment variables, secrets,
private keys, configuration content, or systemd unit content. It is not an
installer and makes no changes to live services.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

RELEVANT=("rule","nft","nat","firewall","wg","wireguard","pool","peer",
          "config","route","apply","render","save","persist","restore",
          "mapping","network","status","address","ip")
NAME=re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$")
ALLOWED_ROOTS=("/usr/local/sbin/", "/opt/cerato-network/")


def inspect(path):
    item=Path(path)
    result={"file":item.name,"exists":False,"python":False,
            "sha256":None,"functions":[],"classes":[],"parser_actions":[],
            "source_bytes":0}
    if not any(str(item).startswith(root) for root in ALLOWED_ROOTS):
        result["error"]="Chemin système hors des répertoires Cerato approuvés"
        return result
    if item.is_symlink() or not item.is_file() or item.stat().st_size>1_000_000:
        result["error"]="Source absente, symbolique ou trop volumineuse"
        return result
    raw=item.read_bytes()
    result["exists"]=True
    result["source_bytes"]=len(raw)
    result["sha256"]=hashlib.sha256(raw).hexdigest()
    try:
        tree=ast.parse(raw.decode("utf-8"))
    except (SyntaxError,UnicodeError,ValueError):
        result["error"]="Source non Python ou syntaxe invalide"
        return result
    result["python"]=True
    funcs=set()
    classes=set()
    actions=set()
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            if NAME.fullmatch(node.name) and any(k in node.name.lower() for k in RELEVANT):
                funcs.add(node.name)
        elif isinstance(node,ast.ClassDef):
            if NAME.fullmatch(node.name):
                classes.add(node.name)
        elif isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
            if node.func.attr=="add_parser" and node.args:
                arg=node.args[0]
                if isinstance(arg,ast.Constant) and isinstance(arg.value,str):
                    if NAME.fullmatch(arg.value.replace("-","_")):
                        actions.add(arg.value)
    result["functions"]=sorted(funcs)[:100]
    result["classes"]=sorted(classes)[:30]
    result["parser_actions"]=sorted(actions)[:80]
    return result


def main():
    p=argparse.ArgumentParser(description="Cerato network engine structural preflight (readonly)")
    p.add_argument("--controller",default="/usr/local/sbin/ceratoctl")
    p.add_argument("--backend",default="/opt/cerato-network/backend/server.py")
    a=p.parse_args()
    print(json.dumps({"format":"cerato-live-network-structure-v1",
                      "modified":False,"sensitive_data_exported":False,
                      "sources":[inspect(a.controller),inspect(a.backend)]},
                     sort_keys=True,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Read-only inventory of the currently deployed Cerato Network console.

Do not send backend source, secrets, SQLite or WireGuard configs to GitHub.
This prints only an allowlisted structure report (hashes, route names, UI
navigation labels, recognized authentication hooks), never source lines,
credentials, network addresses, tokens, peer keys or configuration values.

Designed to prepare a safe in-place account/RBAC migration for port 8787.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

SERVER=Path("/opt/cerato-network/backend/server.py")
CLIENT=Path("/opt/cerato-network/web/app.js")
MAX=2_000_000
ROUTE=re.compile(r"^/api/[a-z0-9/-]{1,100}$")
SAFE_HOOKS={
    "do_GET","do_POST","do_PATCH","do_DELETE","check_session",
    "read_body","send_json","send_error","netstate","auth",
    "get_session","login","logout","csrf","audit",
}
SECTIONS={
    "overview","ips","machines","nat","firewall","topology",
    "logs","settings","updates","accounts","users","security",
}


class InventoryError(Exception):
    pass


def _load(path:Path)->str:
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=MAX:
        raise InventoryError("Fichier du panneau absent, symbolique ou hors limites")
    return path.read_text(encoding="utf8")


def inspect(server:Path=SERVER, frontend:Path=CLIENT)->dict:
    backend=_load(server)
    app=_load(frontend)
    try:
        tree=ast.parse(backend,filename="server.py")
    except SyntaxError as exc:
        raise InventoryError("Backend Python invalide") from exc
    route_names=set()
    funcs=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Constant) and isinstance(node.value,str) and ROUTE.fullmatch(node.value):
            route_names.add(node.value)
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            if node.name in SAFE_HOOKS:
                funcs.add(node.name)
    # Only a fixed vocabulary of sections is reported; script contents
    # and arbitrary JS strings never appear in the output.
    section_names=sorted(name for name in SECTIONS
                         if re.search(r"['\\\"]"+re.escape(name)+r"['\\\"]",app))
    required={"do_GET","do_POST","check_session","read_body"}
    return {
        "format":"cerato-live-auth-compat-v1",
        "server_sha256":hashlib.sha256(backend.encode("utf8")).hexdigest(),
        "frontend_sha256":hashlib.sha256(app.encode("utf8")).hexdigest(),
        "server_bytes":len(backend.encode("utf8")),
        "frontend_bytes":len(app.encode("utf8")),
        "api_routes":sorted(route_names),
        "auth_hooks":sorted(funcs),
        "ui_sections":section_names,
        "compatible_for_adapter_design":required.issubset(funcs),
        "direct_network_mutations":False,
        "note":"Rapport structurel uniquement; aucune migration, secret ou configuration réseau ne sont exportés.",
    }


def main():
    parser=argparse.ArgumentParser(description="Cerato Network — inventaire privé des points d'intégration")
    parser.add_argument("--backend",type=Path,default=SERVER)
    parser.add_argument("--frontend",type=Path,default=CLIENT)
    args=parser.parse_args()
    try:
        report=inspect(args.backend,args.frontend)
    except (InventoryError,OSError,UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2))


if __name__=="__main__":
    main()

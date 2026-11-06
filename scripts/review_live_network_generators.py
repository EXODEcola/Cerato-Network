#!/usr/bin/env python3
"""Safely review only RISE-1's network generator AST to build an exact patch.

Does not import/execute ceratoctl or server.py, does not print raw source,
secrets, string values, peer keys or config values. Literal strings are
always replaced by neutral markers except hardcoded known config key names.
Requires approved SHA256 so it rejects a changed live controller.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

CTL=Path("/usr/local/sbin/ceratoctl")
APPROVED={"render_nft","rewrite_wg_peers","apply"}
SAFE_KEYS={"wan_if","wg_if","pool","mappings","peers","public_ip","peer","ip",
           "pubkey","public_port","target_port","proto","tunnel_cidr",
           "routed_ipv4","mode","additional_ipv4"}
IDENT=re.compile(r"^[A-Za-z_][A-Za-z_0-9]{0,78}$")


def scrub_tree(node):
    result=ast.fix_missing_locations(ast.parse(ast.unparse(node)))
    class StripLiterals(ast.NodeTransformer):
        def visit_Constant(self,item):
            if isinstance(item.value,str):
                return ast.copy_location(
                    ast.Constant(value=item.value if item.value in SAFE_KEYS else "<literal>"),
                    item)
            if isinstance(item.value,bytes):
                return ast.copy_location(ast.Constant(value=b"<redacted>"),item)
            if isinstance(item.value,int) and abs(item.value)>65535:
                return ast.copy_location(ast.Constant(value=0),item)
            return item
    return ast.fix_missing_locations(StripLiterals().visit(result))


def inspect(path,expected_sha):
    if path!=CTL or path.is_symlink() or not path.is_file() or path.stat().st_size>120000:
        raise ValueError("Source contrôleur inconnue ou non approuvée")
    if not re.fullmatch("[a-f0-9]{64}",expected_sha):
        raise ValueError("Empreinte SHA256 non conforme")
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected_sha:
        raise ValueError("Contrôleur modifié depuis l'inspection précédente")
    try:
        tree=ast.parse(raw.decode("utf-8"))
    except (UnicodeError,SyntaxError,ValueError) as exc:
        raise ValueError("Contrôleur non Python ou invalide") from exc
    functions={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in APPROVED:
            if node.name in functions:
                raise ValueError("Fonction réseau dupliquée")
            sanitized=ast.unparse(scrub_tree(node))
            # Hard cap to avoid huge anonymous output or accidental raw dumps.
            if len(sanitized)>12000:
                raise ValueError("Fonction trop volumineuse")
            functions[node.name]=sanitized
    if set(functions)!=APPROVED:
        raise ValueError("Fonctions réseau manquantes")
    return {"format":"cerato-network-redacted-ast-v1","modified":False,
            "controller_sha256":expected_sha,"literal_strings_redacted":True,
            "functions":functions,
            "warning":"Inspecter la sortie et supprimer toute donnée sensible avant partage"}


def main():
    p=argparse.ArgumentParser(description="Cerato network generator AST redacted preview")
    p.add_argument("--controller-sha",required=True)
    args=p.parse_args()
    print(json.dumps(inspect(CTL,args.controller_sha),indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

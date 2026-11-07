#!/usr/bin/env python3
"""Read-only, sanitized execution-boundary inventory of the ACTUAL legacy 8787.

This is NOT permission to start a private backend. It parses the exact,
SHA-pinned production file, checks the inactive candidate and maps only
allowlisted indicators. It never imports or executes private server.py,
modifies accounts, calls networking tools, opens HTTP ports, or exports source.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess

from verify_private_native_auth_stage import (
    BACKUPS, LIVE, TRUSTED_ROOT, EXPECTED, check_one,
    trusted_staging_root, safe_read, digest, VerificationError,
)
from prepare_native_auth_python_runtime import DEST, check_runtime, RuntimePreparationError

EXPECTED_VERBS=frozenset({"do_GET","do_POST","do_PATCH","do_DELETE"})
PRIVILEGE_SETS=("PUBLIC","VIEWER","ADMIN_READ","ADMIN_WRITE","ACCOUNT")
PATH_RX=re.compile(r"^/api/[a-z0-9][a-z0-9/_-]{1,100}$")
KNOWN_SOURCE_PATHS=frozenset({
    "/api/login","/api/logout","/api/status","/api/session","/api/events",
    "/api/ip/allocations","/api/ip/add","/api/ip/remove",
    "/api/ip/preview","/api/ip/configure","/api/peers",
    "/api/peers/remove","/api/nat/add","/api/nat/remove",
    "/api/nft-preview","/api/wg-config","/api/enroll/token",
    "/api/updates","/api/updates/check","/api/updates/install",
    "/api/updates/rollback","/api/updates/stage",
})
MAX_AST_NODES=100_000

class ExecutionBoundaryError(ValueError):
    pass

def candidate_verified():
    trusted_staging_root(BACKUPS,owner=0)
    candidates=[]
    for p in BACKUPS.glob("cerato-private-auth-candidate.*"):
        try:
            check_one(p,live=LIVE,repo=TRUSTED_ROOT,owner=0,pinned=EXPECTED)
            candidates.append(p)
        except (VerificationError,ValueError,OSError,SyntaxError,
                subprocess.TimeoutExpired):
            continue
    if not candidates:
        raise ExecutionBoundaryError("Copie privée approuvée absente ou périmée")
    selected=max(candidates,key=lambda p:p.stat().st_mtime_ns)
    check_one(selected,live=LIVE,repo=TRUSTED_ROOT,owner=0,pinned=EXPECTED)
    return True

def parsed_policy(source:bytes)->set[tuple[str,str]]:
    try:
        tree=ast.parse(source.decode("utf8"),filename="reviewed-policy.py")
    except (SyntaxError,UnicodeError) as exc:
        raise ExecutionBoundaryError("Politique RBAC non analysable") from exc
    groups={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1:
            target=node.targets[0]
            if isinstance(target,ast.Name) and target.id in PRIVILEGE_SETS:
                try:
                    tuples=ast.literal_eval(node.value)
                except (ValueError,TypeError,SyntaxError) as exc:
                    raise ExecutionBoundaryError("Politique RBAC non littérale") from exc
                if (not isinstance(tuples,set) or
                        any(not isinstance(row,tuple) or len(row)!=2 or
                            row[0] not in {"GET","POST","PATCH","DELETE"} or
                            not isinstance(row[1],str) or
                            not PATH_RX.fullmatch(row[1]) for row in tuples)):
                    raise ExecutionBoundaryError("Politique RBAC non approuvée")
                groups[target.id]=tuples
    if set(groups)!=set(PRIVILEGE_SETS):
        raise ExecutionBoundaryError("Ensembles de permissions incomplets")
    flattened=set().union(*groups.values())
    if sum(len(v) for v in groups.values())!=len(flattened):
        raise ExecutionBoundaryError("Routes déclarées avec privilèges ambigus")
    return flattened

def risk_map(source:bytes,policy:bytes)->dict:
    try:
        tree=ast.parse(source.decode("utf8"),filename="private-historical-backend.py")
    except (SyntaxError,UnicodeDecodeError) as exc:
        raise ExecutionBoundaryError("Backend historique non analysable") from exc
    nodes=list(ast.walk(tree))
    if len(nodes)>MAX_AST_NODES:
        raise ExecutionBoundaryError("Backend au-delà des limites du contrôle")
    handlers=[]
    for n in tree.body:
        if not isinstance(n,ast.ClassDef):
            continue
        methods={x.name for x in n.body
                 if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
        if {"do_GET","do_POST","check_session","send_json"}.issubset(methods):
            handlers.append(methods)
    if len(handlers)!=1:
        raise ExecutionBoundaryError("Classe HTTP historique ambiguë")
    methods=handlers[0]
    methods_extra={x for x in methods if x.startswith("do_")} - EXPECTED_VERBS
    source_routes={n.value for n in nodes
                   if isinstance(n,ast.Constant) and isinstance(n.value,str)
                   and PATH_RX.fullmatch(n.value)}
    if len(source_routes)>128:
        raise ExecutionBoundaryError("Routes HTTP trop nombreuses")
    reviewed=parsed_policy(policy)
    reviewed_paths={path for _verb,path in reviewed}|{"/api/login","/api/logout"}
    unknown_routes=source_routes-reviewed_paths
    # Detect potential top-level effects, without executing a single
    # statement or printing implementation details.
    statements=0
    for n in tree.body:
        if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,
                         ast.AsyncFunctionDef,ast.ClassDef,ast.Pass)):
            continue
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            value=n.value
            if value is None or not any(isinstance(x,ast.Call) for x in ast.walk(value)):
                continue
        statements+=1
    network_indicators=sum(
        isinstance(n,ast.Call) and
        ((isinstance(n.func,ast.Name) and n.func.id in {"Popen","system","check_output"})
         or (isinstance(n.func,ast.Attribute) and
             n.func.attr in {"run","Popen","system","bind","connect",
                              "serve_forever","check_output","start_server"}))
        for n in nodes
    )
    return {
        "handler_count":len(handlers),
        "known_http_method_count":len(methods & EXPECTED_VERBS),
        "unwrapped_http_method_count":len(methods_extra),
        "recognized_route_count":len(source_routes & KNOWN_SOURCE_PATHS),
        "unrecognized_api_route_count":len(unknown_routes),
        "rbac_policy_pair_count":len(reviewed),
        "module_level_runtime_statement_count":statements,
        "possible_external_or_socket_call_count":network_indicators,
        "full_backend_execution_review_complete":False,
        "legacy_http_isolation_mandatory":True,
        "http_socket_test_with_actual_backend_complete":False,
    }

def inspect():
    if os.geteuid()!=0:
        raise ExecutionBoundaryError("Contrôle root requis sur la VM OVH")
    original=safe_read(LIVE/"backend/server.py")
    if digest(original)!=EXPECTED["server_sha256"]:
        raise ExecutionBoundaryError("Backend actif différent de l'empreinte auditée")
    policy=safe_read(TRUSTED_ROOT/"security/legacy_policy.py")
    candidate_verified()
    crypto=check_runtime(DEST)
    if not (crypto.get("argon2id_checked") and crypto.get("aes_gcm_checked")):
        raise ExecutionBoundaryError("Bibliothèques natives non vérifiées")
    summary=risk_map(original,policy)
    return {
        "format":"cerato-private-live-http-boundary-v1",
        "production_backend_sha256_verified":True,
        "inactive_candidate_integrity_verified":True,
        "cryptographic_runtime_validated_under_web_user":True,
        **summary,
        "production_modified":False,
        "network_modified":False,
        "nginx_modified":False,
        "service_restarted":False,
        "private_source_exported":False,
        "production_account_created":False,
        "safe_to_execute_private_backend":False,
        "safe_to_cut_over":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--check",action="store_true",required=True)
    p.parse_args()
    try:
        print(json.dumps(inspect(),sort_keys=True,indent=2,ensure_ascii=False))
    except (ExecutionBoundaryError,VerificationError,
            RuntimePreparationError,OSError,ValueError,
            subprocess.TimeoutExpired) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

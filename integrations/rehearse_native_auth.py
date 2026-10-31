#!/usr/bin/env python3
"""Private auth rehearsal against the exact reviewed RISE-1 source bytes.

Never starts the backend, imports the historical server, connects to a live
network socket, calls its tools or edits an installed file. Backend code and
MFA secrets never leave the private temporary directory. This is a structural
rehearsal; it does NOT certify HTTP deployment or authorize Nginx cutover.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from check_live_auth_cutover import BASELINE, GateError, _load_json, assess
from inspect_live_auth_compat import InventoryError, inspect
from inspect_live_handler_flow import HandlerAuditError, audit
from stage_live_auth_backend import StageError, prepare as backend_prepare
from stage_live_auth_frontend import NativeAuthUIStageError, stage as frontend_stage

SOURCE=Path("/opt/cerato-network")
MAX_FILE=2_000_000
class RehearsalError(ValueError):
    pass

def _strict_digest(path:Path):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<MAX_FILE:
        raise RehearsalError("Fichier de production absent ou non régulier")
    return hashlib.sha256(path.read_bytes()).hexdigest()

def rehearse(source:Path=SOURCE, *, baseline:Path=BASELINE,
            backend_runner=backend_prepare,frontend_runner=frontend_stage,
            inspect_source=inspect,inspect_handlers=audit) -> dict:
    source=Path(source)
    if source.is_symlink() or not source.is_dir():
        raise RehearsalError("Source HTTP non reconnue")
    backend=source/"backend/server.py"
    frontend=source/"web/app.js"
    styles=source/"web/style.css"
    before={str(relative):_strict_digest(source/relative) for relative in (
        Path("backend/server.py"),Path("web/app.js"),Path("web/style.css"))}
    trusted=_load_json(baseline)
    inventory=inspect_source(backend,frontend)
    gate=assess(inventory,trusted)
    http=inspect_handlers(backend,frontend)
    if not gate["adapter_design_ready"] or http["candidate_count"]!=1 or http["unclassified_count"]:
        return {
            "format":"cerato-native-auth-rehearsal-v1",
            "verified_exact_source":False,
            "candidate_compiled":False,
            "production_modified":False,"network_modified":False,
            "private_source_exported":False,"release_published":False,
            "production_cutover_ready":False,
            "reason":"source_baseline_or_route_audit_requires_review",
            "baseline_backend_matches":inventory.get("server_sha256")==trusted.get("server_sha256"),
            "baseline_frontend_matches":inventory.get("frontend_sha256")==trusted.get("frontend_sha256"),
        }
    # Private staging is always removed; sources may contain server secrets.
    prior_umask=os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="cerato-auth-rehearsal-") as directory:
            work=Path(directory)
            (work/"backend-stage").parent.chmod(0o700)
            first=backend_runner(backend,work/"backend-stage",baseline=baseline)
            second=frontend_runner(source,work/"frontend-stage",baseline=baseline)
            backend_candidate=work/"backend-stage/backend/server.py"
            client_candidate=work/"frontend-stage/web/app.js"
            with backend_candidate.open("rb") as stream:
                compile(stream.read(),str(backend_candidate),"exec")
            result=subprocess.run(["node","--check",str(client_candidate)],
                                  capture_output=True,timeout=10,check=False)
            if result.returncode:
                raise RehearsalError("Le JS préparé ne passe pas le contrôle de syntaxe")
            if first["production_modified"] or second["production_modified"]:
                raise RehearsalError("Le staging a signalé un changement de production")
            if not first["backend_hash_verified"] or not second["source_backend_verified"]:
                raise RehearsalError("Candidats non conformes à la référence approuvée")
            # The auth modules must be present in the PRIVATE clone only.
            if not (work/"backend-stage/security/live_http_bridge.py").is_file():
                raise RehearsalError("Pont de sessions non copié")
    finally:
        os.umask(prior_umask)
    after={str(relative):_strict_digest(source/relative) for relative in (
        Path("backend/server.py"),Path("web/app.js"),Path("web/style.css"))}
    if before!=after:
        raise RehearsalError("Source locale modifiée pendant la vérification")
    return {
        "format":"cerato-native-auth-rehearsal-v1",
        "verified_exact_source":True,
        "candidate_compiled":True,
        "private_stage_deleted":True,
        "production_modified":False,"network_modified":False,
        "private_source_exported":False,"release_published":False,
        "production_cutover_ready":False,
        "reason":"real_http_cutover_and_signed_rollback_not_yet_tested",
    }

def main():
    cli=argparse.ArgumentParser(description="Répétition PRIVÉE de l'auth Cerato Network, sans démarrage")
    cli.add_argument("--source",type=Path,default=SOURCE)
    cli.add_argument("--baseline",type=Path,default=BASELINE)
    args=cli.parse_args()
    try:
        result=rehearse(args.source,baseline=args.baseline)
    except (RehearsalError,GateError,StageError,NativeAuthUIStageError,
            HandlerAuditError,InventoryError,OSError,ValueError,KeyError,
            TypeError,subprocess.TimeoutExpired) as exc:
        cli.error("Répétition refusée : "+str(exc))
    print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False))
    return 0 if result["candidate_compiled"] else 2

if __name__=="__main__":
    sys.exit(main())

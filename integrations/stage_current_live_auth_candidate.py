#!/usr/bin/env python3
"""Create an INACTIVE private 8787 auth/UI integration candidate on OVH.

Never alters /opt/cerato-network, /etc, Nginx, systemd, SSH, WireGuard,
public IPv4, legacy cookies or the live accounts database.
Never starts an HTTP listener and never exports historical source.

A staging candidate is not a permission to cut over. Current file hashes are
captured only to bind an isolated copy to itself, never to approve production.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from audit_live_8787_auth_cutover import BASE, CutoverAuditError, analyze, source
from stage_live_auth_backend import StageError, prepare
from stage_live_auth_frontend import NativeAuthUIStageError, stage

ROOT=Path(__file__).resolve().parents[1]
BACKUPS=Path("/var/backups")

class PrivateStageError(ValueError):
    pass

def stage_candidate(live:Path=BASE,*,backups:Path=BACKUPS,
                    security_dir:Path=ROOT/"security")->dict:
    live=Path(live)
    for sub in ("backend/server.py","web/app.js","web/style.css"):
        if (live/sub).is_symlink():
            raise PrivateStageError("Fichier de production symbolique : opération refusée")
    backend=source(live/"backend/server.py")
    js=source(live/"web/app.js")
    css=source(live/"web/style.css")
    checked=analyze(backend,js,css)
    if (not checked["http_handler_single_and_unmodified"]
            or not checked["netstate_function_present"]
            or checked["unknown_api_route_count"]
            or not checked["routed_ipv4_api_present"]
            or not checked["routed_nat_guard_present"]
            or not checked["signed_nat_readout_present"]
            or not all(checked["frontend"].values())
            or not all(checked["frontend_sections"].values())
            or not checked["graphite_css_present"]
            or checked["native_auth_overlay_already_inserted"]):
        raise PrivateStageError("Sources HTTP/UI non reconnues : aucune copie préparée")
    if (backups.is_symlink() or not backups.is_dir()
            or backups.stat().st_uid!=os.geteuid()
            or backups.stat().st_mode & (stat.S_IWGRP|stat.S_IWOTH)):
        raise PrivateStageError("Dossier privé des sauvegardes non fiable")
    staging=Path(tempfile.mkdtemp(prefix="cerato-private-auth-candidate.",
                                   dir=backups))
    os.chmod(staging,0o700)
    try:
        baseline=staging/"manifest.json"
        baseline.write_text(json.dumps({
            "format":"cerato-live-auth-baseline-v1",
            "server_sha256":checked["installed_backend_sha256"],
            "frontend_sha256":checked["installed_frontend_sha256"],
            "style_sha256":checked["installed_css_sha256"],
        },sort_keys=True),encoding="utf8")
        baseline.chmod(0o600)
        server=prepare(live/"backend/server.py",staging/"server",
                       baseline=baseline,security_dir=security_dir)
        client=stage(live,staging/"client",baseline=baseline)
        for sub,expected in (
            ("backend/server.py",checked["installed_backend_sha256"]),
            ("web/app.js",checked["installed_frontend_sha256"]),
            ("web/style.css",checked["installed_css_sha256"]),
        ):
            if hashlib.sha256(source(live/sub)).hexdigest()!=expected:
                raise PrivateStageError("Source active modifiée pendant la préparation")
        produced=staging/"server/backend/server.py"
        compile(produced.read_bytes(),str(produced),"exec")
        app=(staging/"client/web/app.js").read_text(encoding="utf8")
        if ("CERATO_AUTH_OVERLAY_STAGING" not in app
                or "async function ceratoLoadIPv4Allocations()" not in app
                or "CERATO-NETWORK-ROUTED-NAT-UI-V1" not in app):
            raise PrivateStageError("Fonctions routage et login absentes de la copie")
        return {
            "format":"cerato-private-8787-auth-candidate-v1",
            "result":"staged_inactive",
            "private_directory":str(staging),
            "backend_compilable":True,
            "frontend_syntax_validated":True,
            "backend_bridge_staged":server["backend_hash_verified"],
            "frontend_overlay_staged":client["source_backend_verified"],
            "source_checksums_match":True,
            "network_modified":False,
            "production_modified":False,
            "service_restarted":False,
            "nginx_modified":False,
            "production_cutover_approved":False,
            "safe_to_disable_legacy_login":False,
            "contains_private_source":True,
            "warning":"Ne pas copier ce dossier vers GitHub ni le distribuer en release.",
        }
    except BaseException:
        # Only a uniquely generated private path under the caller-supplied
        # approved staging directory can ever be removed.
        shutil.rmtree(staging)
        raise

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--stage",action="store_true",required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:
        parser.error("Étape privée réservée à root sur OVH")
    try:
        result=stage_candidate()
    except (PrivateStageError,CutoverAuditError,NativeAuthUIStageError,
            StageError,OSError,ValueError,UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))

if __name__=="__main__":
    main()

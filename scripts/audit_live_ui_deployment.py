#!/usr/bin/env python3
"""Read-only report: why a live Cerato 8787 Web panel lacks routed IPv4 UI.

Does NOT import the live backend, execute its code, call privileged network
controllers, expose keys/cookies/passwords or mutate system state.
Reports only SHA-256 fingerprints and structural feature-presence booleans.
Designed for RISE-1's historical Web app, which is NOT the standalone
development web/app.js checked into the GitHub repository.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

DEFAULT_WEB=Path("/opt/cerato-network")
DEFAULT_STATE=Path("/var/lib/cerato-network-updates/state.json")

def read_regular(path,limit):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Fichier introuvable ou symbolique : "+str(path))
    length=path.stat().st_size
    if length<=0 or length>limit:
        raise ValueError("Fichier hors limites : "+str(path))
    return path.read_bytes()

def audit(web=DEFAULT_WEB,state=DEFAULT_STATE):
    if web.is_symlink() or not web.is_dir():
        raise ValueError("Panneau Web absent ou symbolique")
    names={
        "backend/server.py":"backend",
        "web/app.js":"frontend",
        "web/style.css":"style",
    }
    raw={}
    hashes={}
    for relative,name in names.items():
        blob=read_regular(web/relative,400_000)
        raw[name]=blob.decode("utf8")
        hashes[name]=hashlib.sha256(blob).hexdigest()
    backend=raw["backend"]
    frontend=raw["frontend"]
    update={}
    if state.exists() or state.is_symlink():
        metadata=json.loads(read_regular(state,50_000))
        if not isinstance(metadata,dict):
            raise ValueError("État updater incorrect")
        update={
            "installed_version":metadata.get("installed_version"),
            "available_version":metadata.get("available_version"),
            "reason_code":metadata.get("reason_code"),
        }
    checks={
        "legacy_graphite_frontend":frontend.count("function render(){if(!live)return;")==1,
        "legacy_update_view":frontend.count("function updates(){")==1,
        "legacy_backend_network_status":backend.count("def netstate():")==1,
        "live_additional_ip_helper":backend.count("def additional_ipctl(")==1,
        "live_nat_post_route":len(re.findall(
            r"(?m)^ {8,24}if p=='/api/nat(?:/add)?':",backend))==1,
        "authenticated_status_get":len(re.findall(
            r"(?m)^ {8,24}if p=='/api/status': return self\.send_json\(200,netstate\(\)\)",
            backend))==1,
        "routed_allocations_api_installed":"/api/ip/allocations" in backend,
        "routed_ipv4_ui_installed":"function ceratoEnhanceIPv4()" in frontend,
        "legacy_updater_present":"/api/updates" in backend,
        "legacy_nat_banner_present":"Une règle NAT redirige un port vers WireGuard" in frontend,
    }
    baseline_possible=all(checks[k] for k in (
        "legacy_graphite_frontend","legacy_update_view",
        "legacy_backend_network_status","live_additional_ip_helper",
        "live_nat_post_route","authenticated_status_get"
    ))
    return {
        "schema":"cerato-live-ui-release-audit-v1",
        "hashes":hashes,"update":update,"checks":checks,
        "candidate_for_safe_staging":baseline_possible and
            not checks["routed_allocations_api_installed"] and
            not checks["routed_ipv4_ui_installed"],
        "safe_to_apply_automatically":False,
        "production_modified":False,"network_modified":False,
        "release_required":"signed, vetted legacy-Web 8787 overlay, not a GitHub source build",
    }

def main():
    parser=argparse.ArgumentParser(description="Cerato: read-only panel release readiness")
    parser.add_argument("--web",type=Path,default=DEFAULT_WEB)
    parser.add_argument("--state",type=Path,default=DEFAULT_STATE)
    args=parser.parse_args()
    try:
        report=audit(args.web,args.state)
    except (OSError,UnicodeError,ValueError,KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2))

if __name__=="__main__":
    main()

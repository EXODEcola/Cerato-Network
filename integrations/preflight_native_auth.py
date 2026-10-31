#!/usr/bin/env python3
"""Local, read-only migration evidence for the private RISE-1 web console.

Never exports the backend/frontend, password hashes, Nginx dumps, cookies,
wireguard keys, network configs, or account details. Never patches/restarts.

This is NOT a production cutover authorization; it always says false.
Run it locally on OVH only, after a normal Git pull, if desired.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
from pathlib import Path
import stat
import subprocess
import sys

from check_live_auth_cutover import BASELINE, GateError, _load_json, assess
from inspect_live_auth_compat import InventoryError, SERVER, CLIENT, inspect
from inspect_live_handler_flow import HandlerAuditError, audit
from inspect_live_login_layers import inspect_layers, nginx_layer

AUTH_STORE=Path("/var/lib/cerato-network-auth")
AUTH_SERVICE="cerato-network-web.service"
ALLOWED_UNIT_KEYS=("User","ProtectSystem","ProtectHome","PrivateTmp",
                   "NoNewPrivileges","ReadWritePaths")


def _systemd_unit(*,runner=subprocess.run):
    try:
        result=runner(["systemctl","show",AUTH_SERVICE,
                       *[f"-p{key}" for key in ALLOWED_UNIT_KEYS]],
                      capture_output=True,timeout=8,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return {"inspection":"unavailable"}
    if result.returncode or len(result.stdout)>12000:
        return {"inspection":"unavailable"}
    data={}
    for line in result.stdout.decode("utf8","replace").splitlines():
        key,sep,value=line.partition("=")
        if sep and key in ALLOWED_UNIT_KEYS:
            data[key]=value
    return {
        "inspection":"structural",
        "web_user_expected":data.get("User")=="ceratonet",
        "strict_filesystem":data.get("ProtectSystem")=="strict",
        "protect_home":data.get("ProtectHome")=="yes",
        "private_tmp":data.get("PrivateTmp")=="yes",
        "auth_store_write_scope_declared":AUTH_STORE.as_posix() in data.get("ReadWritePaths","").split(),
        # An elevated server would need to be explicitly configured, not
        # inferred from the current working sudoers entries.
        "root_permissions_unchanged":True,
    }


def _auth_directory(path:Path=AUTH_STORE, *, expected_uid:int|None=None):
    # os.lstat detects an existing symlink without following it.
    try:
        st=path.lstat()
    except FileNotFoundError:
        return {"state":"not_initialized","requires_private_storage_setup":True}
    except OSError:
        return {"state":"unavailable","requires_private_storage_setup":True}
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        return {"state":"unsafe_permissions","requires_private_storage_setup":True}
    if expected_uid is None:
        try:
            expected_uid=pwd.getpwnam("ceratonet").pw_uid
        except KeyError:
            return {"state":"service_identity_unavailable","requires_private_storage_setup":True}
    if st.st_uid!=expected_uid:
        return {"state":"wrong_owner","requires_private_storage_setup":True}
    return {"state":"private_directory_exists","requires_private_storage_setup":False}


def summarize(backend:Path=SERVER,frontend:Path=CLIENT,baseline:Path=BASELINE,
              *,unit_checker=_systemd_unit,login_checker=nginx_layer)->dict:
    # The reports expose only fixed field names and allowlisted route labels.
    inventory=inspect(backend,frontend)
    check=assess(inventory,_load_json(baseline))
    handler=audit(backend,frontend)
    safe_handlers=[{
        "verbs":row["verbs"],
        "has_check_session_method":row["has_check_session_method"],
        "conditional_route_counts":{name:len(paths) for name,paths in row["conditional_routes"].items()},
        "reachable_session_check_counts":{name:stats["check_session"]
             for name,stats in row["reachable_call_counts"].items()},
    } for row in handler["handler_candidates"]]
    nginx=login_checker()
    service=unit_checker()
    store=_auth_directory()
    blockers=[]
    if not check["adapter_design_ready"]:
        blockers.append("live_source_not_identical_to_reviewed_baseline")
    if handler["candidate_count"]!=1 or handler["unclassified_count"]!=0:
        blockers.append("http_handler_routes_not_fully_reviewed")
    if not isinstance(nginx,dict) or nginx.get("inspection")!="structural":
        blockers.append("nginx_layer_not_verified")
    if service.get("inspection")!="structural" or not service.get("web_user_expected"):
        blockers.append("web_service_identity_not_verified")
    if not service.get("auth_store_write_scope_declared"):
        blockers.append("auth_store_not_in_web_service_writable_paths")
    if store.get("requires_private_storage_setup"):
        blockers.append("auth_store_not_prepared_with_private_permissions")
    blockers.extend((
        "historical_login_retirement_and_csrf_review_pending",
        "browser_mfa_and_recovery_e2e_on_private_clone_pending",
        "reversible_signed_migration_not_approved",
    ))
    return {
        "format":"cerato-native-auth-local-preflight-v1",
        "production_cutover_ready":False,
        "live_code_exported":False,
        "secret_values_exported":False,
        "network_modified":False,
        "web_service_modified":False,
        "baseline_matches":check["source_hashes_match"],
        "reviewed_routes_complete":not check["missing_known_routes"] and
            not check["unexpected_route_count"],
        "missing_known_routes":check["missing_known_routes"],
        "unexpected_route_count":check["unexpected_route_count"],
        "http_handler_candidates":handler["candidate_count"],
        "unclassified_known_route_count":handler["unclassified_count"],
        "http_handler_summary":safe_handlers,
        "legacy_auth_endpoints_present":sorted(set(inventory["api_routes"]) &
            {"/api/login","/api/logout"}),
        "nginx_auth_basic_declared":nginx.get("http_basic_declared") if isinstance(nginx,dict) else None,
        "nginx_effective_security_not_proven":True,
        "web_service_security":service,
        "auth_storage":store,
        "blockers":sorted(set(blockers)),
    }


def main():
    parser=argparse.ArgumentParser(description="Cerato Network : preflight lecture seule Owner/Admin/User")
    parser.add_argument("--backend",type=Path,default=SERVER)
    parser.add_argument("--frontend",type=Path,default=CLIENT)
    parser.add_argument("--baseline",type=Path,default=BASELINE)
    args=parser.parse_args()
    try:
        report=summarize(args.backend,args.frontend,args.baseline)
    except (InventoryError,HandlerAuditError,GateError,OSError,ValueError,
            UnicodeError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":
    sys.exit(main())

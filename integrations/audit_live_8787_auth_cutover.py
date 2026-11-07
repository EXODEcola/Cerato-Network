#!/usr/bin/env python3
"""Cerato Network 8787: immutable, redacted authorization cutover inventory.

This inspects the REAL installed backend/UI following v0.1.2-beta.1.
It never imports/executes backend code, reads credentials/account records,
modifies systemd/Nginx, connects to a network service, or changes routes.
Never print or upload the private backend to GitHub.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

BASE=Path("/opt/cerato-network")
WEB_SERVICE="cerato-network-web.service"
KNOWN_ROUTES=frozenset({
    "/api/login","/api/logout","/api/status","/api/session",
    "/api/peers","/api/peers/remove","/api/enroll/token",
    "/api/ip/add","/api/ip/remove","/api/ip/preview","/api/ip/configure",
    "/api/ip/allocations","/api/nat/add","/api/nat/remove",
    "/api/events","/api/wg-config","/api/nft-preview",
    "/api/updates","/api/updates/check","/api/updates/install",
    "/api/updates/rollback","/api/updates/stage",
})
API_RE=re.compile(r"^/api/[a-z0-9][a-z0-9/_-]{1,100}$")
MAX_BYTES=2_000_000
MAX_NGINX=3_000_000
REQUIRED_METHODS=frozenset({"check_session","send_json","do_GET","do_POST","read_body"})
REQUIRED_SECTIONS=frozenset({
    "overview","ips","machines","nat","firewall",
    "topology","logs","settings","updates",
})
FRONTEND_MARKERS={
    "render_hook":"function render(){if(!live)return;",
    "bind_hook":"function bind(){",
    "updates_hook":"function updates(){",
    "routed_ipv4_loader":"async function ceratoLoadIPv4Allocations()",
    "routed_ipv4_overlay":"function ceratoEnhanceIPv4()",
    "routed_nat_readout":"function ceratoRenderDirectRoutedIPv4(",
}
AUTH_MARKER="CERATO_AUTH_OVERLAY_STAGING"
NAT_UI_MARKER="CERATO-NETWORK-ROUTED-NAT-UI-V1"

class CutoverAuditError(ValueError):
    pass

def source(path:Path)->bytes:
    if path.is_symlink() or not path.is_file():
        raise CutoverAuditError("Source absente ou symbolique")
    if not 0<path.stat().st_size<=MAX_BYTES:
        raise CutoverAuditError("Taille de source incompatible")
    return path.read_bytes()

def run_readonly(*cmd,limit=8):
    try:
        result=subprocess.run(cmd,text=True,capture_output=True,
                              check=False,timeout=limit)
        return result if len(result.stdout)<MAX_NGINX else None
    except (OSError,subprocess.TimeoutExpired):
        return None

def systemd_status():
    fields={
        "User":"ceratonet",
        "ProtectSystem":"strict",
        "ProtectHome":"yes",
        "PrivateTmp":"yes",
    }
    args=["/usr/bin/systemctl","show",WEB_SERVICE,
          *[("-p"+key) for key in fields],
          "-pReadWritePaths","-pNoNewPrivileges"]
    p=run_readonly(*args)
    if not p or p.returncode:
        return {"inspection":"unavailable"}
    options=dict(line.split("=",1) for line in p.stdout.splitlines()
                 if "=" in line)
    paths=options.get("ReadWritePaths","").split()
    return {
        "inspection":"structural",
        "web_user_expected":options.get("User")==fields["User"],
        "protect_system_strict":options.get("ProtectSystem")=="strict",
        "protect_home":options.get("ProtectHome")=="yes",
        "private_tmp":options.get("PrivateTmp")=="yes",
        "no_new_privileges":options.get("NoNewPrivileges")=="yes",
        "auth_storage_write_scope":
            "/var/lib/cerato-network-auth" in paths,
        "service_active":bool(
            (p2:=run_readonly("/usr/bin/systemctl","is-active","--quiet",WEB_SERVICE))
            and p2.returncode==0),
    }

def proxy_status():
    p=run_readonly("/usr/sbin/nginx","-T")
    if p is None or p.returncode:
        return {"inspection":"unavailable"}
    s=p.stdout
    basic=bool(re.search(r"(?m)^\s*auth_basic\s+(?!off\s*;)[^;]+;",s))
    return {
        "inspection":"directive_presence_only",
        "basic_auth_present_somewhere":basic,
        "native_auth_http_cutover_verified":False,
    }

def account_storage():
    root=Path("/var/lib/cerato-network-auth")
    try:
        user=pwd.getpwnam("ceratonet")
        entry=root.lstat()
        trusted=(stat.S_ISDIR(entry.st_mode)
                 and entry.st_uid==user.pw_uid
                 and entry.st_gid==user.pw_gid
                 and stat.S_IMODE(entry.st_mode)==0o700)
        return {"trusted_directory":trusted,
                "exists":True,
                "database_exists":(root/"accounts.sqlite3").is_file() if trusted else False}
    except (FileNotFoundError,KeyError,OSError):
        return {"trusted_directory":False,"exists":False,"database_exists":False}

def analyze(backend:bytes,frontend:bytes,styles:bytes):
    try:
        backend_text=backend.decode("utf8")
        js=frontend.decode("utf8")
        css=styles.decode("utf8")
        tree=ast.parse(backend_text,filename="legacy-8787.py")
    except (SyntaxError,UnicodeDecodeError) as exc:
        raise CutoverAuditError("Syntaxe ou encodage de l'installation incompatible") from exc
    candidates=[]
    for node in tree.body:
        if not isinstance(node,ast.ClassDef):
            continue
        methods={part.name for part in node.body if isinstance(part,ast.FunctionDef)}
        if {"do_GET","do_POST","check_session"}.issubset(methods):
            candidates.append((node,methods))
    structurally_valid=(len(candidates)==1 and
        REQUIRED_METHODS.issubset(candidates[0][1]) and
        not candidates[0][0].decorator_list)
    strings={node.value for node in ast.walk(tree)
             if isinstance(node,ast.Constant) and isinstance(node.value,str)
             and API_RE.fullmatch(node.value)}
    frontend_markers={k:js.count(marker)==1 for k,marker in FRONTEND_MARKERS.items()}
    sections={name: bool(re.search(r"['\"]"+re.escape(name)+r"['\"]",js))
              for name in sorted(REQUIRED_SECTIONS)}
    backend_decorators=(
        len(candidates[0][0].decorator_list) if candidates else 0)
    return {
        "schema":"cerato-live-8787-auth-cutover-audit-v2",
        "installed_backend_sha256":hashlib.sha256(backend).hexdigest(),
        "installed_frontend_sha256":hashlib.sha256(frontend).hexdigest(),
        "installed_css_sha256":hashlib.sha256(styles).hexdigest(),
        "backend_bytes":len(backend),
        "frontend_bytes":len(frontend),
        "http_handler_single_and_unmodified":structurally_valid,
        "handler_candidate_count":len(candidates),
        "handler_decorator_count":backend_decorators,
        "netstate_function_present":any(isinstance(n,ast.FunctionDef)
                      and n.name=="netstate" for n in tree.body),
        "reviewed_api_route_count":len(strings & KNOWN_ROUTES),
        "unknown_api_route_count":len(strings-KNOWN_ROUTES),
        "legacy_login_route_present":"/api/login" in strings,
        "legacy_logout_route_present":"/api/logout" in strings,
        "routed_ipv4_api_present":"/api/ip/allocations" in strings,
        "routed_nat_guard_present":"cerato_reject_routed_nat(" in backend_text,
        "frontend":frontend_markers,
        "frontend_sections":sections,
        "native_auth_overlay_already_inserted":AUTH_MARKER in js,
        "signed_nat_readout_present":NAT_UI_MARKER in js,
        "graphite_css_present":"CERATO NETWORK — Graphite Operations" in css,
    }

def report(base:Path=BASE,systemd=systemd_status,proxy=proxy_status,
           account=account_storage):
    state=analyze(source(base/"backend/server.py"),
                  source(base/"web/app.js"),source(base/"web/style.css"))
    state["systemd"]=systemd()
    state["proxy"]=proxy()
    state["accounts_storage"]=account()
    ready=(state["http_handler_single_and_unmodified"]
       and state["netstate_function_present"]
       and state["routed_ipv4_api_present"]
       and state["routed_nat_guard_present"]
       and state["unknown_api_route_count"]==0
       and all(state["frontend"].values())
       and all(state["frontend_sections"].values())
       and not state["native_auth_overlay_already_inserted"])
    state["candidate_staging_eligible"]=bool(ready)
    state["safe_to_cut_over"]=False
    state["safe_to_disable_legacy_login"]=False
    state["safe_to_modify_nginx"]=False
    state["production_modified"]=False
    state["network_modified"]=False
    state["private_source_exported"]=False
    state["private_account_records_exported"]=False
    return state

def main():
    arg=argparse.ArgumentParser()
    arg.add_argument("--check",action="store_true",required=True)
    opt=arg.parse_args()
    try:
        print(json.dumps(report(),ensure_ascii=False,sort_keys=True,indent=2))
    except (CutoverAuditError,OSError,ValueError,TypeError) as exc:
        arg.error(str(exc))

if __name__=="__main__":
    main()

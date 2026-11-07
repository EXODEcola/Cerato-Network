#!/usr/bin/env python3
"""Verify a private, INACTIVE legacy 8787 native-auth candidate after staging.

Reads /var/backups/cerato-private-auth-candidate.* and current live hashes.
NEVER executes private backend Python, imports its security modules, creates
an account/database, sends HTTP traffic or modifies production/service/network.
No source code, secrets or arbitrary paths are included in the JSON result.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

LIVE=Path("/opt/cerato-network")
BACKUPS=Path("/var/backups")
WEB_SERVICE="cerato-network-web.service"
STORE=Path("/var/lib/cerato-network-auth")
TRUSTED_ROOT=Path(__file__).resolve().parents[1]
VERSION="v0.1.2-beta.1"
EXPECTED={
    "server_sha256":"0e5a7a41ae88fbbf7c1de49a9471a1ab521e174515f7a18b47b761542697c324",
    "frontend_sha256":"b4ae1e20cedb1c761c2bb8f8d2da04d612e16963d5edc2f1c7273203716f5232",
    "style_sha256":"431687f01d1c3adfbf0e150a459fe25ef2e1fffb7b4d05b734efd2d54dac75f5",
}
SECURITY_MODULES=(
    "auth_store.py","mfa.py","secretbox.py","legacy_policy.py",
    "live_session_guard.py","legacy_auth_api.py","live_http_bridge.py",
)
MAX_BYTES=2_000_000
MARKERS_JS=(
    "CERATO_AUTH_OVERLAY_STAGING",
    "CERATO_LEGACY_NAV_PERSISTENCE_V1",
    "CERATO-NETWORK-ROUTED-NAT-UI-V1",
    "async function ceratoLoadIPv4Allocations()",
)
ALLOWED_STAGE_PREFIX="cerato-private-auth-candidate."

class VerificationError(ValueError):
    pass

def safe_read(file:Path, *, owner:int|None=None, mode:int|None=None):
    if file.is_symlink() or not file.is_file() or not 0<file.stat().st_size<=MAX_BYTES:
        raise VerificationError("Fichier absent, symbolique ou volumineux")
    info=file.stat()
    if owner is not None and info.st_uid!=owner:
        raise VerificationError("Propriétaire du fichier non reconnu")
    if mode is not None and stat.S_IMODE(info.st_mode)!=mode:
        raise VerificationError("Permissions du fichier non reconnues")
    return file.read_bytes()

def safe_directory(path:Path,*,owner:int,mode:int):
    if path.is_symlink() or not path.is_dir():
        raise VerificationError("Répertoire privé absent ou symbolique")
    st=path.stat()
    if st.st_uid!=owner or stat.S_IMODE(st.st_mode)!=mode:
        raise VerificationError("Répertoire privé aux permissions non approuvées")

def digest(raw:bytes):
    return hashlib.sha256(raw).hexdigest()

def trusted_staging_root(root:Path=BACKUPS):
    if root.is_symlink() or not root.is_dir():
        raise VerificationError("Racine des sauvegardes absente ou symbolique")
    entry=root.stat()
    if entry.st_uid!=0 or entry.st_mode & (stat.S_IWGRP|stat.S_IWOTH):
        raise VerificationError("Racine des sauvegardes non fiable")

def check_one(candidate:Path,*,live=LIVE,repo=TRUSTED_ROOT,owner=0,pinned=EXPECTED):
    if candidate.parent!=BACKUPS or not candidate.name.startswith(ALLOWED_STAGE_PREFIX):
        raise VerificationError("Chemin de copie privée non approuvé")
    safe_directory(candidate,owner=owner,mode=0o700)
    manifest=json.loads(safe_read(candidate/"manifest.json",owner=owner,mode=0o600))
    if (not isinstance(manifest,dict)
            or manifest.get("format")!="cerato-live-auth-baseline-v1"
            or {k:manifest.get(k) for k in EXPECTED}!=pinned):
        raise VerificationError("Manifeste privé incompatible avec l'audit approuvé")
    root_sources={
        "server_sha256":live/"backend/server.py",
        "frontend_sha256":live/"web/app.js",
        "style_sha256":live/"web/style.css",
    }
    for k,path in root_sources.items():
        if digest(safe_read(path))!=manifest[k]:
            raise VerificationError("La version Web de production a changé")
    for rel in ("server","server/backend","server/security","client","client/web"):
        safe_directory(candidate/rel,owner=owner,mode=0o700)
    staged_backend=safe_read(candidate/"server/backend/server.py",
                             owner=owner,mode=0o600)
    active_backend=safe_read(live/"backend/server.py")
    if (staged_backend.count(b"CERATO_AUTH_BRIDGE_STAGED")!=1
            or active_backend.count(b"CERATO_AUTH_BRIDGE_STAGED")!=0):
        raise VerificationError("Pont d'authentification déjà présent ou absent")
    compile(staged_backend,"private-backend-candidate.py","exec")
    for module in SECURITY_MODULES:
        copied=safe_read(candidate/"server/security"/module,
                         owner=owner,mode=0o600)
        trusted=safe_read(repo/"security"/module)
        if digest(copied)!=digest(trusted):
            raise VerificationError("Un module de sécurité de la copie est différent de GitHub")
        compile(copied,module,"exec")
    js=safe_read(candidate/"client/web/app.js",owner=owner,mode=0o600)
    css=safe_read(candidate/"client/web/style.css",owner=owner,mode=0o600)
    for marker in MARKERS_JS:
        if js.count(marker.encode())!=1:
            raise VerificationError("Marqueur JavaScript absent ou dupliqué")
    if b"cerato-auth" not in css.lower():
        # The old Graphite CSS remains present; the explicit native login
        # classes must be appended to the private candidate only.
        raise VerificationError("Style d'authentification absent")
    result=subprocess.run(["node","--check","-"],input=js,
                          capture_output=True,timeout=14,check=False)
    if result.returncode:
        raise VerificationError("Syntaxe JavaScript du candidat invalide")
    return True

def service_context():
    try:
        p=subprocess.run(["/usr/bin/systemctl","show",WEB_SERVICE,
                          "-p","User","-p","ReadWritePaths","-p","Environment",
                          "-p","NoNewPrivileges"],
                         text=True,capture_output=True,timeout=10)
        if p.returncode:
            return {"inspected":False}
        opts=dict(line.split("=",1) for line in p.stdout.splitlines() if "=" in line)
    except (OSError,subprocess.TimeoutExpired):
        return {"inspected":False}
    return {
        "inspected":True,
        "user_is_ceratonet":opts.get("User")=="ceratonet",
        "private_auth_storage_writable":str(STORE) in opts.get("ReadWritePaths","").split(),
        "https_origin_declared":bool(re.search(
            r"(?:^|\s)CERATO_WEB_ORIGIN=https://",opts.get("Environment",""))),
        # NoNewPrivileges=false currently enables the narrowly scoped
        # cerato-ipctl status sudo read; never change it during this check.
        "no_new_privileges_changed":False,
    }

def storage_state():
    try:
        user=pwd.getpwnam("ceratonet")
        stat_result=STORE.lstat()
        trusted=(stat.S_ISDIR(stat_result.st_mode)
                 and stat_result.st_uid==user.pw_uid
                 and stat_result.st_gid==user.pw_gid
                 and stat.S_IMODE(stat_result.st_mode)==0o700)
    except (KeyError,FileNotFoundError,OSError):
        trusted=False
    return {"directory_ready":bool(trusted),
            "new_account_created":False,
            "database_read":False}

def inspect(*,root=BACKUPS,live=LIVE,repo=TRUSTED_ROOT,
            pinned=EXPECTED,owner=0):
    trusted_staging_root(root)
    eligible=[]
    for candidate in root.glob(ALLOWED_STAGE_PREFIX+"*"):
        # Never follow symbolic links or entries outside the approved root.
        try:
            # The check_one production path constraint stays pinned to BACKUPS.
            if root==BACKUPS:
                check_one(candidate,live=live,repo=repo,owner=owner,pinned=pinned)
                eligible.append(candidate)
        except (VerificationError,ValueError,OSError,SyntaxError,
                subprocess.TimeoutExpired):
            continue
    if not eligible:
        raise VerificationError("Aucune copie privée conforme à la version auditée")
    selected=max(eligible,key=lambda p:p.stat().st_mtime_ns)
    # A repeat check closes the small source-change window before reporting.
    check_one(selected,live=live,repo=repo,owner=owner,pinned=pinned)
    runtime={
        "argon2":importlib.util.find_spec("argon2") is not None,
        "cryptography":importlib.util.find_spec("cryptography") is not None,
    }
    context=service_context()
    storage=storage_state()
    return {
        "format":"cerato-private-native-auth-verified-v1",
        "installed_version_required":VERSION,
        "candidate_count_verified":len(eligible),
        "candidate_integrity_verified":True,
        "private_backend_compiled":True,
        "private_frontend_js_checked":True,
        "security_modules_match_trusted_source":True,
        "current_web_sources_match_verified_audit":True,
        "runtime_dependencies":runtime,
        "service_context":context,
        "private_storage":storage,
        "prerequisites_satisfied":(
            all(runtime.values()) and
            context.get("user_is_ceratonet") and
            context.get("private_auth_storage_writable") and
            context.get("https_origin_declared") and
            storage["directory_ready"]),
        "safe_to_cut_over":False,
        "production_modified":False,
        "network_modified":False,
        "web_restarted":False,
        "private_source_exported":False,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check",action="store_true",required=True)
    parser.parse_args()
    if os.geteuid()!=0:
        parser.error("Exécuter en root uniquement sur RISE-1")
    try:
        report=inspect()
    except (VerificationError,OSError,ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report,sort_keys=True,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()

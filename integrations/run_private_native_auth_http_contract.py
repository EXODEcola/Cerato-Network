#!/usr/bin/env python3
"""Non-network, post-venv native-auth smoke test on an APPROVED private copy.

Revalidates the staged live backend SHA and copied security modules, then
runs only the verified security modules under the real unprivileged
ceratonet account, with a disposable SQLite database in /var/tmp.
No HTTP listener, real login, account DB, systemd or network modification.
Outputs booleans only. It does NOT approve the production cutover.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

from verify_private_native_auth_stage import (
    BACKUPS, LIVE, EXPECTED, SECURITY_MODULES, check_one, trusted_staging_root,
    VerificationError,
)
from prepare_native_auth_python_runtime import DEST, check_runtime, RuntimePreparationError

REPO=Path(__file__).resolve().parents[1]
TEST=REPO/"tests/private_native_auth_http_contract.py"
RUNUSER="/usr/sbin/runuser"
WEB_USER="ceratonet"

class SandboxError(ValueError):
    pass

# Exact allowlist: no child traceback, secret, account, IP or arbitrary text
# can be reflected from the untrusted subprocess output.
DIAGNOSTIC_STAGES=frozenset((
    "startup","arguments","module-import","temporary-database",
    "bootstrap-owner","bridge-attachment","legacy-session-denial",
    "owner-password","owner-mfa","owner-authorized-status",
    "origin-csrf","create-secondary-accounts","admin-password",
    "admin-mfa","owner-account-protection","viewer-login",
    "viewer-redaction","account-list","legacy-login-rejection",
    "complete",
))
DIAGNOSTIC_MODULES=frozenset((
    "argon2","argon2.exceptions","argon2._password_hasher",
    "cryptography","cryptography.hazmat","cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cffi","_cffi_backend","typing_extensions",
    "mfa","secretbox","auth_store","legacy_auth_api",
    "legacy_policy","live_session_guard","live_http_bridge",
    "sqlite3","_sqlite3","http","http.cookies","urllib",
    "dataclasses",
))
DIAGNOSTIC_ERRORS=frozenset((
    "AssertionError","PermissionError","FileNotFoundError","OSError",
    "RuntimeError","ValueError","TypeError","ImportError",
    "ModuleNotFoundError","OperationalError","IntegrityError",
    "ProgrammingError","Forbidden","InvalidCredentials",
    "AuthError","SecretBoxError",
))
def error_phase(stdout:str,stderr:str):
    # Extract only metadata from our own child; NEVER display full stderr
    # (which may include unrelated source text, credentials or paths).
    found_phase=re.findall(r"(?m)^CERATO_TEST_STAGE=([a-z][a-z0-9-]{0,55})$",stderr[:16000])
    found_type=re.findall(r"(?m)^CERATO_TEST_ERROR=([A-Za-z][A-Za-z0-9]{0,55})$",stderr[:16000])
    phase=found_phase[-1] if found_phase and found_phase[-1] in DIAGNOSTIC_STAGES else "unknown"
    error=found_type[-1] if found_type and found_type[-1] in DIAGNOSTIC_ERRORS else "unknown"
    found_module=re.findall(r"(?m)^CERATO_TEST_MODULE=([A-Za-z_][A-Za-z0-9_.]{0,95})$",stderr[:16000])
    missing=found_module[-1] if found_module and found_module[-1] in DIAGNOSTIC_MODULES else "unknown"
    return phase,error,missing

def verified_candidate():
    trusted_staging_root(BACKUPS,owner=0)
    valid=[]
    for candidate in BACKUPS.glob("cerato-private-auth-candidate.*"):
        try:
            check_one(candidate,live=LIVE,repo=REPO,owner=0,pinned=EXPECTED)
            valid.append(candidate)
        except (VerificationError,ValueError,OSError,SyntaxError,
                subprocess.TimeoutExpired):
            continue
    if not valid:
        raise SandboxError("Aucune copie privée liée à l'installation actuelle")
    selected=max(valid,key=lambda p:p.stat().st_mtime_ns)
    check_one(selected,live=LIVE,repo=REPO,owner=0,pinned=EXPECTED)
    return selected

def check_test_source():
    if TEST.is_symlink() or not TEST.is_file() or TEST.stat().st_uid!=0:
        raise SandboxError("Scénario de validation privé non approuvé")
    if TEST.stat().st_size>30_000:
        raise SandboxError("Scénario de validation trop volumineux")

def stage_sandbox(root:Path,candidate:Path,user):
    # Only PUBLIC repo modules and a synthetic test script are copied here.
    # Allow traverse of the two root-owned dirs without relying on OVH's
    # supplementary group mapping (the reported auth_store import failed).
    # Mode 0755 permits Python module-directory scanning but NO write access.
    # Real auth data remains solely in the user-owned 0700 test-only-db.
    os.chown(root,0,0)
    os.chmod(root,0o755)
    modules=root/"security"
    modules.mkdir(mode=0o700)
    os.chown(modules,0,0)
    os.chmod(modules,0o755)
    files=[(candidate/"server/security"/name,modules/name)
           for name in SECURITY_MODULES]
    files.append((TEST,root/"run-contract.py"))
    for origin,target in files:
        if origin.is_symlink() or not origin.is_file():
            raise SandboxError("Un module privé n'est plus un fichier ordinaire")
        # check_one already verifies the seven module hashes. Compare again
        # immediately before copying to avoid a local source-change race.
        if origin!=TEST:
            repo_file=REPO/"security"/origin.name
            if origin.read_bytes()!=repo_file.read_bytes():
                raise SandboxError("Un module privé a changé depuis la vérification")
        shutil.copyfile(origin,target)
        # Contents are exact verified PUBLIC source files with fictitious
        # credentials, never a production backend or real MFA database.
        # Read-only world access here avoids relying on primary-group
        # inheritance across runuser / PAM / host-specific group settings.
        os.chown(target,0,0)
        os.chmod(target,0o644)
    storage=root/"test-only-db"
    storage.mkdir(mode=0o700)
    os.chown(storage,user.pw_uid,user.pw_gid)
    os.chmod(storage,0o700)
    return root/"run-contract.py",modules,storage

def run():
    if os.geteuid()!=0:
        raise SandboxError("Vérification réservée à root sur Cerato Network OVH")
    if not Path(RUNUSER).is_file():
        raise SandboxError("Outil d'exécution avec compte Web absent")
    check_test_source()
    runtime=check_runtime(DEST)
    if not (runtime.get("argon2id_checked") and runtime.get("aes_gcm_checked")):
        raise SandboxError("Environnement cryptographique incomplet")
    user=pwd.getpwnam(WEB_USER)
    candidate=verified_candidate()
    root=Path(tempfile.mkdtemp(prefix="cerato-auth-contract.",dir="/var/tmp"))
    try:
        script,security,storage=stage_sandbox(root,candidate,user)
        result=subprocess.run(
            [RUNUSER,"-u",WEB_USER,"--",str(DEST/"bin/python"),"-I",
             str(script),str(security),str(storage)],
            timeout=120,capture_output=True,text=True,check=False,
        )
        if result.returncode:
            # Never forward potentially private tracebacks to the operator.
            phase,error,missing=error_phase(result.stdout,result.stderr)
            raise SandboxError(
                "Tests HTTP/MFA isolés refusés : étape="+phase+
                ", type="+error+
                (", module_manquant="+missing if error=="ModuleNotFoundError" else "")+
                ". Aucun compte actif modifié")
        try:
            payload=json.loads(result.stdout)
        except ValueError as exc:
            raise SandboxError("Réponse du test isolé non JSON") from exc
        required=(
            "owner_enrolled_with_mfa","admin_enrolled_with_mfa",
            "user_read_only_and_redacted","owner_account_protected",
            "csrf_and_origin_enforced","historical_login_rejected",
            "http_handlers_in_memory","test_database_temporary",
        )
        if (payload.get("format")!="cerato-native-auth-sandbox-v1"
                or not all(payload.get(x) is True for x in required)
                or payload.get("production_network_used") is not False
                or payload.get("production_accounts_used") is not False
                or payload.get("safe_to_cut_over") is not False):
            raise SandboxError("Contrats de sécurité incomplets")
        return {
            "status":"private_auth_contract_passed",
            "format":"cerato-private-auth-contract-v1",
            "owner_mfa_checked":True,
            "admin_mfa_checked":True,
            "viewer_rbac_checked":True,
            "csrf_origin_checked":True,
            "legacy_login_disabled_in_candidate":True,
            "http_contract_requests":payload.get("test_requests_checked"),
            "crypto_runtime_approved":True,
            "production_accounts_modified":False,
            "production_backend_imported":False,
            "production_modified":False,
            "network_modified":False,
            "service_restarted":False,
            "safe_to_cut_over":False,
        }
    finally:
        # The test-only account database, simulated MFA seeds and passwords
        # never survive the sandbox. Do not delete anything outside this path.
        if root.parent==Path("/var/tmp") and root.name.startswith("cerato-auth-contract.") and not root.is_symlink():
            shutil.rmtree(root)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check",action="store_true",required=True)
    parser.parse_args()
    try:
        print(json.dumps(run(),sort_keys=True,indent=2))
    except (SandboxError,RuntimePreparationError,VerificationError,
            OSError,ValueError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()

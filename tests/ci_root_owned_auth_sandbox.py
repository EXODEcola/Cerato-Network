#!/usr/bin/env python3
"""Linux integration test: exact root-owned 0750/0640 sandbox + runuser.

Run ONLY in disposable GitHub Actions runner as root via sudo. It uses
nobody/nogroup and a fresh test-only SQLite database in /var/tmp.
No network listener and no production files are opened.
"""
from __future__ import annotations
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SECURITY=(
    "auth_store.py","mfa.py","secretbox.py","legacy_policy.py",
    "live_session_guard.py","legacy_auth_api.py","live_http_bridge.py",
)

def run():
    if os.geteuid()!=0:
        raise RuntimeError("Simulation des permissions root requise")
    user=pwd.getpwnam("nobody")
    sandbox=Path(tempfile.mkdtemp(prefix="cerato-ci-root-sandbox.",dir="/var/tmp"))
    try:
        os.chown(sandbox,0,user.pw_gid)
        os.chmod(sandbox,0o750)
        security=sandbox/"security"
        security.mkdir(mode=0o750)
        os.chown(security,0,user.pw_gid)
        script=sandbox/"run-contract.py"
        for p in SECURITY:
            target=security/p
            shutil.copyfile(ROOT/"security"/p,target)
            os.chown(target,0,user.pw_gid)
            os.chmod(target,0o640)
        shutil.copyfile(ROOT/"tests/private_native_auth_http_contract.py",script)
        os.chown(script,0,user.pw_gid)
        os.chmod(script,0o640)
        storage=sandbox/"test-only-db"
        storage.mkdir(mode=0o700)
        os.chown(storage,user.pw_uid,user.pw_gid)
        os.chmod(storage,0o700)
        # Exercise a real isolated venv, not the Actions/system Python.
        binary=os.environ.get("CERATO_AUTH_CI_PYTHON",sys.executable)
        if not Path(binary).is_file():
            raise RuntimeError("Python de test isolé absent")
        command=[
            "/usr/sbin/runuser","-u",user.pw_name,"--",binary,
            "-I",str(script),str(security),str(storage)
        ]
        p=subprocess.run(command,capture_output=True,text=True,timeout=110)
        if p.returncode!=0:
            # This is disposable CI ONLY. No production credentials or
            # private backend are present in this synthetic root sandbox.
            raise RuntimeError("Sandbox Linux failed; private CI traceback:\n"+p.stderr[-3500:])
        import json
        result=json.loads(p.stdout)
        assert result["owner_enrolled_with_mfa"]
        assert result["admin_enrolled_with_mfa"]
        assert result["user_read_only_and_redacted"]
        assert result["safe_to_cut_over"] is False
        print("PASS: real unprivileged runuser sandbox with test-only auth lifecycle")
    finally:
        shutil.rmtree(sandbox)

if __name__=="__main__":
    run()

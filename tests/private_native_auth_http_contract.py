#!/usr/bin/env python3
"""INACTIVE auth bridge contract test using only copied, audited security modules.

Expected argv: <private security dir> <disposable test-only db directory>.
The caller must create a non-public temporary directory owned by the test
user; this process NEVER touches the real account database, controller,
network state, production backend or listener port. No credentials are output.
"""
from __future__ import annotations
import io
import json
from pathlib import Path
import sys
import time

# Emits ONLY an approved phase identifier, exception class and (for a
# ModuleNotFoundError) an exact allowlisted public module name on failure.
# Never expose traceback values, database contents, passwords or MFA seeds.
_MISSING_MODULE_ALLOWLIST=frozenset((
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
_STAGE = "startup"
def mark(phase):
    global _STAGE
    _STAGE = phase

def run():
    mark("arguments")
    if len(sys.argv)!=3:
        raise RuntimeError("Arguments incomplets")
    security=Path(sys.argv[1])
    storage=Path(sys.argv[2])
    if security.is_symlink() or not security.is_dir() or storage.is_symlink() or not storage.is_dir():
        raise RuntimeError("Répertoires de test non approuvés")
    if any(storage.iterdir()):
        raise RuntimeError("Stockage du test non vierge")
    mark("module-import")
    sys.path.insert(0,str(security))
    from auth_store import AuthStore, Forbidden, InvalidCredentials
    from mfa import code_for_counter
    from live_http_bridge import wrap_legacy_handler

    mark("temporary-database")
    store=AuthStore(storage/"accounts.sqlite3")
    assert not store.is_initialized()
    mark("bootstrap-owner")
    bootstrap=store.issue_bootstrap_token()
    owner=store.setup_owner(bootstrap,"owner@cerato.invalid","Test-Owner-Passphrase-98173!")
    assert owner["role"]=="owner"
    assert store.is_initialized()

    class Handler:
        def __init__(self, method, path, *, cookie="", csrf="", origin=None,
                     host="51.210.223.57", payload=None):
            raw=json.dumps(payload if payload is not None else {}).encode()
            self.path=path
            self.headers={
                "Host":host,
                "Cookie":cookie,
                "X-Cerato-CSRF":csrf,
                "Origin":("https://51.210.223.57" if origin is None else origin),
                "Content-Type":"application/json",
                "Content-Length":str(len(raw)),
            }
            self.client_address=("127.0.0.1",41021)
            self.rfile=io.BytesIO(raw)
            self.wfile=io.BytesIO()
            self.status=None
            self.reply_headers={}
            self.legacy_calls=0
            self.data=None

        def check_session(self,write=False):
            # An original legacy password must NEVER authorize native sessions.
            return False

        def send_response(self,code):
            self.status=code

        def send_header(self,name,value):
            self.reply_headers[name]=value

        def end_headers(self):
            pass

        def send_json(self,code,payload):
            self.status=code
            self.data=payload

        def do_GET(self):
            self.legacy_calls+=1
            if not self.check_session():
                return self.send_json(401,{"error":"legacy-login"})
            return self.send_json(200,{
                "dashboard_mode":"live",
                "tunnel_active":True,
                "timestamp":int(time.time()),
                "peers":{"dell-r530":{"last_handshake":int(time.time())}},
                "private_key":"TEST-DO-NOT-EXPOSE",
                "ip":"198.51.100.35",
            })

        def do_POST(self):
            self.legacy_calls+=1
            if not self.check_session(write=True):
                return self.send_json(401,{"error":"legacy-login"})
            return self.send_json(200,{"ok":True})

        def do_PATCH(self):
            self.legacy_calls+=1
            return self.send_json(500,{"error":"legacy-patch-not-allowed"})

        def do_DELETE(self):
            self.legacy_calls+=1
            return self.send_json(500,{"error":"legacy-delete-not-allowed"})

    mark("bridge-attachment")
    wrap_legacy_handler(Handler,store,allowed_origin="https://51.210.223.57")
    calls=0
    def request(method,path,**kwargs):
        nonlocal calls
        handler=Handler(method,path,**kwargs)
        getattr(handler,"do_"+method)()
        calls+=1
        body=json.loads(handler.wfile.getvalue()) if handler.wfile.getvalue() else handler.data
        return handler, body

    mark("legacy-session-denial")
    unauthorized,_=request("GET","/api/status",cookie="cerato_session=old-password")
    assert unauthorized.status==403 and unauthorized.legacy_calls==0

    mark("owner-password")
    login,challenge=request("POST","/api/auth/login",payload={
        "email":"owner@cerato.invalid","password":"Test-Owner-Passphrase-98173!",
    })
    assert login.status==200 and challenge["mfa_required"]
    assert challenge["mfa_setup"] and "otp_secret" in challenge
    assert "Set-Cookie" not in login.reply_headers

    mark("owner-mfa")
    totp=code_for_counter(challenge["otp_secret"],int(time.time())//30)
    finished,confirmed=request("POST","/api/auth/mfa/verify",payload={
        "challenge":challenge["challenge"],"code":totp,
    })
    assert finished.status==200 and confirmed["account"]["role"]=="owner"
    assert "recovery_codes" in confirmed
    assert "HttpOnly" in finished.reply_headers["Set-Cookie"]
    assert "Secure" in finished.reply_headers["Set-Cookie"]
    assert "SameSite=Strict" in finished.reply_headers["Set-Cookie"]
    owner_cookie=finished.reply_headers["Set-Cookie"].split(";",1)[0]
    owner_csrf=confirmed["csrf"]

    mark("owner-authorized-status")
    owner_status,owner_data=request("GET","/api/status",cookie=owner_cookie)
    assert owner_status.status==200 and owner_status.legacy_calls==1
    assert owner_data.get("private_key")=="TEST-DO-NOT-EXPOSE"

    mark("origin-csrf")
    badcsrf,_=request("POST","/api/nat/add",cookie=owner_cookie,csrf="bad")
    assert badcsrf.status==403 and badcsrf.legacy_calls==0
    badorigin,_=request("POST","/api/nat/add",cookie=owner_cookie,
                        csrf=owner_csrf,origin="https://untrusted.invalid")
    assert badorigin.status==403 and badorigin.legacy_calls==0
    allowed,_=request("POST","/api/nat/add",cookie=owner_cookie,csrf=owner_csrf)
    assert allowed.status==200 and allowed.legacy_calls==1

    mark("create-secondary-accounts")
    created_admin,admin_data=request("POST","/api/accounts",
        cookie=owner_cookie,csrf=owner_csrf,payload={
            "email":"admin@cerato.invalid",
            "password":"Test-Admin-Passphrase-98173!",
            "role":"admin",
        })
    assert created_admin.status==201 and admin_data["account"]["role"]=="admin"
    created_user,user_data=request("POST","/api/accounts",
        cookie=owner_cookie,csrf=owner_csrf,payload={
            "email":"viewer@cerato.invalid",
            "password":"Test-Viewer-Passphrase-98173!",
            "role":"user",
        })
    assert created_user.status==201 and user_data["account"]["role"]=="user"

    mark("admin-password")
    admin_login,challenge2=request("POST","/api/auth/login",payload={
        "email":"admin@cerato.invalid","password":"Test-Admin-Passphrase-98173!",
    })
    assert admin_login.status==200 and challenge2["mfa_required"]
    assert "Set-Cookie" not in admin_login.reply_headers
    mark("admin-mfa")
    code2=code_for_counter(challenge2["otp_secret"],int(time.time())//30)
    admin_done,admin_result=request("POST","/api/auth/mfa/verify",payload={
        "challenge":challenge2["challenge"],"code":code2,
    })
    assert admin_done.status==200 and admin_result["account"]["role"]=="admin"
    admin_cookie=admin_done.reply_headers["Set-Cookie"].split(";",1)[0]
    admin_csrf=admin_result["csrf"]

    mark("owner-account-protection")
    account_protection,_=request("PATCH","/api/accounts/"+str(owner["id"]),
        cookie=admin_cookie,csrf=admin_csrf,payload={"active":False})
    assert account_protection.status==403 and account_protection.legacy_calls==0

    mark("viewer-login")
    viewer_login,vinfo=request("POST","/api/auth/login",payload={
        "email":"viewer@cerato.invalid","password":"Test-Viewer-Passphrase-98173!",
    })
    assert viewer_login.status==200 and vinfo["account"]["role"]=="user"
    assert "mfa_required" not in vinfo
    viewer_cookie=viewer_login.reply_headers["Set-Cookie"].split(";",1)[0]
    viewer_csrf=vinfo["csrf"]
    mark("viewer-redaction")
    view,summary=request("GET","/api/status",cookie=viewer_cookie)
    assert view.status==200 and summary.get("tunnel_active") is True
    assert "private_key" not in summary and "ip" not in summary and "peers" not in summary
    viewer_mutation,_=request("POST","/api/nat/add",cookie=viewer_cookie,
        csrf=viewer_csrf)
    assert viewer_mutation.status==403 and viewer_mutation.legacy_calls==0
    viewer_accounts,_=request("GET","/api/accounts",cookie=viewer_cookie)
    assert viewer_accounts.status==403

    mark("account-list")
    list_handler,account_list=request("GET","/api/accounts",cookie=owner_cookie)
    assert list_handler.status==200 and len(account_list["accounts"])==3
    assert all(set(row)=={"id","email","role","active","mfa_enabled",
                          "active_sessions"} for row in account_list["accounts"])
    mark("legacy-login-rejection")
    legacy_login,_=request("POST","/api/login",payload={
        "password":"historical-placeholder",
    })
    assert legacy_login.status==410 and legacy_login.legacy_calls==0
    hostile_host,_=request("GET","/api/status",cookie=owner_cookie,
                            host="attacker.invalid")
    assert hostile_host.status==403 and hostile_host.legacy_calls==0
    unknown,_=request("POST","/not-api/manage",
        cookie=owner_cookie,csrf=owner_csrf)
    assert unknown.status==404 and unknown.legacy_calls==0
    direct_secret="TEST-DO-NOT-EXPOSE"
    data=storage/"accounts.sqlite3"
    assert data.is_file() and "private_key" not in str(account_list)
    output={
        "format":"cerato-native-auth-sandbox-v1",
        "owner_enrolled_with_mfa":True,
        "admin_enrolled_with_mfa":True,
        "user_read_only_and_redacted":True,
        "owner_account_protected":True,
        "csrf_and_origin_enforced":True,
        "historical_login_rejected":True,
        "http_handlers_in_memory":True,
        "test_requests_checked":calls,
        "test_database_temporary":True,
        "production_network_used":False,
        "production_accounts_used":False,
        "live_backend_imported":False,
        "safe_to_cut_over":False,
    }
    encoded=json.dumps(output,sort_keys=True)
    assert direct_secret not in encoded
    mark("complete")
    print(encoded)

if __name__=="__main__":
    try:
        run()
    except Exception as exc:
        # Purely diagnostic metadata: never echo exception messages.
        print("CERATO_TEST_STAGE="+_STAGE,file=sys.stderr)
        print("CERATO_TEST_ERROR="+type(exc).__name__,file=sys.stderr)
        if isinstance(exc,ModuleNotFoundError) and exc.name in _MISSING_MODULE_ALLOWLIST:
            print("CERATO_TEST_MODULE="+exc.name,file=sys.stderr)
        sys.exit(1)

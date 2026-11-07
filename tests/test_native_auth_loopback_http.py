"""Loopback-only HTTP contract for native 8787 auth, WITHOUT the OVH backend.

Real HTTP parser, cookies, CSRF, Origin and Argon2/TOTP modules. Deliberately
uses a synthetic network handler, not /opt/cerato-network/backend/server.py.
GitHub Actions only; binds 127.0.0.1 on an ephemeral port, never port 8787.
"""
from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import AuthStore
from live_http_bridge import wrap_legacy_handler
from mfa import code_for_counter

ORIGIN="https://panel.example.test"
HOST="panel.example.test"


class NativeAuthHTTPContract(unittest.TestCase):
    def test_real_loopback_http_owner_admin_viewer_and_mfa(self):
        with tempfile.TemporaryDirectory(prefix="cerato-standalone-http.") as d:
            storage=Path(d)/"accounts.sqlite3"
            store=AuthStore(storage)
            traffic={"legacy_get":0,"legacy_write":0}
            class SyntheticLegacy(BaseHTTPRequestHandler):
                # Always a different test-only listener; never port 8787.
                protocol_version="HTTP/1.0"

                def log_message(self,*args):
                    pass

                def check_session(self,write=False):
                    # The obsolete password must never authorize a request.
                    return False

                def send_json(self,status,payload,*_args,**_kwargs):
                    encoded=json.dumps(payload).encode("utf8")
                    self.send_response(status)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Content-Length",str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)

                def do_GET(self):
                    traffic["legacy_get"]+=1
                    if not self.check_session():
                        return self.send_json(401,{"error":"obsolete-login"})
                    return self.send_json(200,{
                        "dashboard_mode":"test",
                        "tunnel_active":True,
                        "peers":{"test-peer":{"latest_handshake":0}},
                        "private_key":"NEVER-EXPOSE-TO-VIEWER",
                        "ip":"192.0.2.77",
                    })

                def do_POST(self):
                    traffic["legacy_write"]+=1
                    if not self.check_session(write=True):
                        return self.send_json(401,{"error":"obsolete-login"})
                    return self.send_json(200,{"ok":True})

                def do_PATCH(self):
                    traffic["legacy_write"]+=1
                    return self.send_json(500,{"error":"legacy-unsafe-patch"})

                def do_DELETE(self):
                    traffic["legacy_write"]+=1
                    return self.send_json(500,{"error":"legacy-unsafe-delete"})

            wrap_legacy_handler(SyntheticLegacy,store,allowed_origin=ORIGIN)
            srv=ThreadingHTTPServer(("127.0.0.1",0),SyntheticLegacy)
            port=srv.server_address[1]
            self.assertNotEqual(port,8787)
            loop=threading.Thread(target=srv.serve_forever,daemon=True)
            loop.start()
            total=0
            def request(method,path,body=None,cookie=None,csrf=None,
                        origin=ORIGIN,host=HOST):
                nonlocal total
                conn=http.client.HTTPConnection("127.0.0.1",port,timeout=5)
                payload=json.dumps(body).encode("utf8") if body is not None else None
                headers={"Host":host,"Accept":"application/json"}
                if payload is not None:
                    headers["Content-Type"]="application/json"
                if cookie:headers["Cookie"]=cookie
                if csrf:headers["X-Cerato-CSRF"]=csrf
                if origin:headers["Origin"]=origin
                try:
                    conn.request(method,path,body=payload,headers=headers)
                    res=conn.getresponse()
                    data=res.read()
                    output=json.loads(data.decode()) if data else {}
                    result=(res.status,output,res.getheader("Set-Cookie"),
                            dict(res.getheaders()))
                    total+=1
                    return result
                finally:
                    conn.close()
            try:
                status,body,*_=request("GET","/api/auth/setup-status")
                self.assertEqual(status,200)
                self.assertFalse(body["initialized"])
                bootstrap=store.issue_bootstrap_token()
                status,body,*_=request("POST","/api/auth/setup",{
                    "token":bootstrap,"email":"owner@test.invalid",
                    "password":"Owner-Cerato-Test-Strong-Passphrase1!",
                })
                self.assertEqual(status,201)
                self.assertEqual(body["account"]["role"],"owner")
                status,body,token,_=request("POST","/api/auth/login",{
                    "email":"owner@test.invalid",
                    "password":"Owner-Cerato-Test-Strong-Passphrase1!",
                })
                self.assertEqual(status,200)
                self.assertTrue(body["mfa_required"])
                self.assertIsNone(token)
                self.assertTrue(body["mfa_setup"])
                status,authenticated,auth_cookie,_=request(
                    "POST","/api/auth/mfa/verify",{
                        "challenge":body["challenge"],
                        "code":code_for_counter(body["otp_secret"],int(time.time())//30),
                    })
                self.assertEqual(status,200)
                self.assertEqual(authenticated["account"]["role"],"owner")
                self.assertTrue(all(x in auth_cookie for x in
                                    ("HttpOnly","Secure","SameSite=Strict")))
                cookie=auth_cookie.split(";",1)[0]
                csrf=authenticated["csrf"]

                status,_,_,_=request("GET","/api/status",cookie="cerato_session=obsolete")
                self.assertEqual(status,403)
                status,owner_data,_,_=request("GET","/api/status",cookie=cookie)
                self.assertEqual(status,200)
                self.assertEqual(owner_data["private_key"],
                                 "NEVER-EXPOSE-TO-VIEWER")
                status,_,_,_=request("POST","/api/nat/add",{},
                                    cookie=cookie,csrf="forged")
                self.assertEqual(status,403)
                status,_,_,_=request("POST","/api/nat/add",{},
                                    cookie=cookie,csrf=csrf,
                                    origin="https://attacker.invalid")
                self.assertEqual(status,403)
                status,_,_,_=request("POST","/api/nat/add",{},
                                    cookie=cookie,csrf=csrf,host="attacker.invalid")
                self.assertEqual(status,403)
                status,_,_,_=request("POST","/api/nat/add",{},cookie=cookie,csrf=csrf)
                self.assertEqual(status,200)
                self.assertEqual(traffic["legacy_write"],1)

                status,account,_,_=request("POST","/api/accounts",{
                    "email":"viewer@test.invalid",
                    "password":"Viewer-Cerato-Test-Strong-Passphrase1!",
                    "role":"user",
                },cookie=cookie,csrf=csrf)
                self.assertEqual(status,201)
                self.assertEqual(account["account"]["role"],"user")
                status,account,_,_=request("POST","/api/accounts",{
                    "email":"admin@test.invalid",
                    "password":"Admin-Cerato-Test-Strong-Passphrase1!",
                    "role":"admin",
                },cookie=cookie,csrf=csrf)
                self.assertEqual(status,201)
                self.assertEqual(account["account"]["role"],"admin")

                status,viewer,viewer_token,_=request("POST","/api/auth/login",{
                    "email":"viewer@test.invalid",
                    "password":"Viewer-Cerato-Test-Strong-Passphrase1!",
                })
                self.assertEqual(status,200)
                self.assertEqual(viewer["account"]["role"],"user")
                viewer_cookie=viewer_token.split(";",1)[0]
                viewer_csrf=viewer["csrf"]
                status,redacted,_,_=request("GET","/api/status",cookie=viewer_cookie)
                self.assertEqual(status,200)
                self.assertTrue(redacted.get("tunnel_active"))
                for forbidden in ("private_key","ip","peers"):
                    self.assertNotIn(forbidden,redacted)
                status,_,_,_=request("POST","/api/nat/add",{},
                                     cookie=viewer_cookie,csrf=viewer_csrf)
                self.assertEqual(status,403)
                status,_,_,_=request("GET","/api/accounts",cookie=viewer_cookie)
                self.assertEqual(status,403)

                status,admin_challenge,no_cookie,_=request("POST","/api/auth/login",{
                    "email":"admin@test.invalid",
                    "password":"Admin-Cerato-Test-Strong-Passphrase1!",
                })
                self.assertEqual(status,200)
                self.assertTrue(admin_challenge["mfa_required"])
                self.assertIsNone(no_cookie)
                status,admin,admin_token,_=request("POST","/api/auth/mfa/verify",{
                    "challenge":admin_challenge["challenge"],
                    "code":code_for_counter(admin_challenge["otp_secret"],
                                            int(time.time())//30),
                })
                self.assertEqual(status,200)
                self.assertEqual(admin["account"]["role"],"admin")
                status,_,_,_=request("PATCH","/api/accounts/1",{
                    "active":False},cookie=admin_token.split(";",1)[0],
                    csrf=admin["csrf"])
                self.assertEqual(status,403)

                status,_,_,_=request("POST","/api/login",{"password":"obsolete"})
                self.assertEqual(status,410)
                status,_,_,_=request("GET","/api/auth/unreviewed",cookie=cookie)
                self.assertEqual(status,404)
                status,_,_,_=request("POST","/not-api/manage",{},cookie=cookie,csrf=csrf)
                self.assertEqual(status,404)
                status,me,_,_=request("GET","/api/auth/me",cookie=cookie)
                self.assertEqual(status,200)
                self.assertEqual(me["account"]["role"],"owner")
                status,_,logout_cookie,_=request("POST","/api/auth/logout",{},
                                                 cookie=cookie,csrf=me["csrf"])
                self.assertEqual(status,200)
                self.assertIn("Max-Age=0",logout_cookie)
                status,_,_,_=request("GET","/api/status",cookie=cookie)
                self.assertEqual(status,403)
                self.assertTrue(storage.exists())
                self.assertGreaterEqual(total,21)
            finally:
                srv.shutdown()
                srv.server_close()
                loop.join(timeout=3)
            # TemporaryDirectory removes the fictitious DB at test exit.
            self.assertTrue(srv.socket.fileno()<0)


if __name__=="__main__":
    unittest.main()

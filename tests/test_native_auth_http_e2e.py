"""Integration contract for the future 8787 native-auth HTTP bridge.

Only starts a disposable localhost HTTP server in CI. It never invokes
ceratoctl, touches SSH, signs releases or changes RISE-1.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request as HTTPRequest, urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import Forbidden,InvalidCredentials
from live_http_bridge import wrap_legacy_handler

ORIGIN="https://panel.example.test"

class IsolatedStore:
    def __init__(self):
        self.role="owner"
        self.actions=[]
    def actor(self,session):
        if session!="current-session":
            raise InvalidCredentials("No valid session")
        return {"id":1,"role":self.role,"active":True}
    def verify_csrf(self,session,csrf):
        if csrf!="current-csrf":
            raise Forbidden("Invalid CSRF")
    def require_permission(self,actor,permission):
        if actor["role"]=="user" and permission!="view":
            raise Forbidden("Read-only")
    def is_initialized(self):return True
    def login(self,email,password,source_ip):
        if password!="test-password":
            raise InvalidCredentials("Bad credential")
        return {"mfa_required":True,"mfa_setup":False,"challenge":"pending"}
    def complete_mfa(self,challenge,code):
        if challenge!="pending" or code!="654321":
            raise InvalidCredentials("Bad second factor")
        return {"session":"current-session","csrf":"current-csrf",
                "account":{"id":1,"role":"owner","active":True}}

def handler_type(store):
    class Legacy(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def _json(self,code,value):
            body=json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        send_json=_json
        def check_session(self,write=False):
            # The legacy password MUST be rejected. Only the bridge may
            # temporarily override this after validating the native session.
            return False
        def do_GET(self):
            if self.path=="/api/status":
                if not self.check_session():return self._json(401,{"error":"legacy-login"})
                return self._json(200,{"dashboard_mode":"real","tunnel_active":True,
                    "peers":{"dell":{"last_handshake":0,"ip":"10.77.0.2"}},
                    "gateway_private_key":"must-never-leak"})
            return self._json(404,{"error":"not-found"})
        def do_POST(self):
            if not self.check_session(write=True):return self._json(401,{"error":"legacy-login"})
            if self.path=="/api/nat/add":
                store.actions.append("nat-add")
                return self._json(200,{"ok":True})
            return self._json(404,{"error":"not-found"})
    return wrap_legacy_handler(Legacy,store,allowed_origin=ORIGIN,
        viewer_status_provider=lambda: {
            "dashboard_mode":"real","tunnel_active":True,
            "peers":{"dell":{"last_handshake":0,"ip":"10.77.0.2"}},
            "gateway_private_key":"must-never-leak"
        })

class EndToEndLocalHTTPBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store=IsolatedStore()
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),handler_type(cls.store))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def invoke(self,route,method="GET",payload=None,cookie=None,csrf=None,origin=None):
        headers={"Host":"panel.example.test"}
        if cookie:headers["Cookie"]="cerato_session="+cookie
        if csrf:headers["X-Cerato-CSRF"]=csrf
        if origin:headers["Origin"]=origin
        body=None if payload is None else json.dumps(payload).encode()
        if body is not None:headers["Content-Type"]="application/json"
        request=HTTPRequest(
            f"http://127.0.0.1:{self.server.server_port}"+route,
            data=body,headers=headers,method=method)
        try:
            with urlopen(request,timeout=4) as response:
                return response.status,json.loads(response.read())
        except HTTPError as error:
            return error.code,json.loads(error.read())

    def test_anonymous_cannot_read_or_mutate(self):
        for route,verb,body in [
            ("/api/status","GET",None),
            ("/api/nat/add","POST",{})
        ]:
            code,_=self.invoke(route,verb,body,origin=ORIGIN)
            self.assertEqual(code,403)
        self.assertEqual(self.store.actions,[])

    def test_owner_write_requires_correct_csrf_and_origin(self):
        self.store.role="owner"
        self.store.actions=[]
        for origin,csrf in ((None,"current-csrf"),(ORIGIN,None),
                            (ORIGIN,"obsolete-csrf"),("https://evil.test","current-csrf")):
            code,_=self.invoke("/api/nat/add","POST",{},cookie="current-session",
                               csrf=csrf,origin=origin)
            self.assertEqual(code,403)
            self.assertEqual(self.store.actions,[])
        code,_=self.invoke("/api/nat/add","POST",{},cookie="current-session",
                           csrf="current-csrf",origin=ORIGIN)
        self.assertEqual(code,200)
        self.assertEqual(self.store.actions,["nat-add"])

    def test_viewer_receives_only_allowlisted_status(self):
        self.store.role="user"
        code,payload=self.invoke("/api/status",cookie="current-session")
        self.assertEqual(code,200)
        self.assertEqual(payload["dashboard_mode"],"real")
        for secret in ("gateway_private_key","peers","10.77.0.2"):
            self.assertNotIn(secret,json.dumps(payload))
        code,_=self.invoke("/api/nat/add","POST",{},cookie="current-session",
                           csrf="current-csrf",origin=ORIGIN)
        self.assertEqual(code,403)

    def test_legacy_login_rejected_and_password_requires_mfa(self):
        self.store.role="owner"
        before=list(self.store.actions)
        code,_=self.invoke("/api/login","POST",{},origin=ORIGIN)
        self.assertEqual(code,410)
        code,payload=self.invoke("/api/auth/login","POST",
                    {"email":"a@example.test","password":"test-password"},origin=ORIGIN)
        self.assertEqual(code,200)
        self.assertTrue(payload["mfa_required"])
        self.assertNotIn("session",payload)
        code,payload=self.invoke("/api/auth/mfa/verify","POST",
                    {"challenge":"pending","code":"654321"},origin=ORIGIN)
        self.assertEqual(code,200)
        self.assertIn("csrf",payload)
        self.assertNotIn("session",payload)
        self.assertEqual(self.store.actions,before)

    def test_unreviewed_routes_deny_before_legacy(self):
        self.store.role="owner"
        code,_=self.invoke("/api/debug/admin","GET",cookie="current-session")
        self.assertEqual(code,403)

if __name__=="__main__":
    unittest.main()

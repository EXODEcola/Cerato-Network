"""Executable contract: all old API traffic is gated before the old code runs.

Uses a fake handler/store, does not bind ports or touch the production server.
"""
from __future__ import annotations

import io
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import Forbidden, InvalidCredentials
from live_http_bridge import LiveHTTPBridge, wrap_legacy_handler, LiveBridgeError


class Store:
    def __init__(self):
        self.role = "owner"
        self.checked = []
        self.saved = []

    def actor(self, token):
        self.checked.append(("actor", token))
        if token != "new-session":
            raise InvalidCredentials("no session")
        return {"id": 2, "active": True, "role": self.role}

    def verify_csrf(self, token, csrf):
        self.checked.append(("csrf", csrf))
        if csrf != "ok-csrf":
            raise Forbidden("csrf")

    def require_permission(self, actor, permission):
        self.checked.append(("permission", permission))
        if actor["role"] == "user" and permission != "view":
            raise Forbidden("cannot modify")

    def is_initialized(self):
        return True

    def login(self, email, password, source_ip):
        self.checked.append(("login", email))
        if password != "valid-password":
            raise InvalidCredentials("bad password")
        return {"mfa_required":True,"challenge":"pending","mfa_setup":False}

    def complete_mfa(self, challenge, code):
        self.checked.append(("mfa", challenge))
        if code != "123456":
            raise InvalidCredentials("bad otp")
        return {"session":"new-session", "csrf":"ok-csrf",
                "account":{"id":2,"role":"owner","active":True}}


class Handler:
    def __init__(self, path, *, method="GET", cookie="", csrf="", origin="",
                 payload=b'{}', content_type="application/json", host="panel.example.net"):
        self.path=path
        self.headers={
            "Host":host, "Cookie":cookie, "Origin":origin,
            "X-Cerato-CSRF":csrf, "Content-Length":str(len(payload)),
            "Content-Type":content_type,
        }
        self.client_address=("127.0.0.1",37810)
        self.rfile=io.BytesIO(payload)
        self.wfile=io.BytesIO()
        self.calls=[]
        self.status=200
        self.output_headers={}

    def send_response(self, code):
        self.status=code

    def send_header(self, key, value):
        self.output_headers[key]=value

    def end_headers(self):
        pass

    def send_json(self, code, data):
        self.status=code
        self.saved=data

    def check_session(self, write=False):
        self.calls.append(("legacy-session",write))
        return False

    def do_GET(self):
        self.calls.append(("legacy-GET",self.path))
        if not self.check_session():
            return self.send_json(401,{"error":"legacy-login"})
        return self.send_json(200, {"tunnel_active":True,
             "dashboard_mode":"real","timestamp":12345,
             "peers":{"dell-r530":{"last_handshake":12345}},
             "private_key":"must-not-leak","ip":"54.37.165.151"})

    def do_POST(self):
        self.calls.append(("legacy-POST",self.path))
        if not self.check_session(write=True):
            return self.send_json(403,{"error":"legacy-forbidden"})
        self.saved={"ok":True}


class LiveHTTPBridgeTests(unittest.TestCase):
    def setUp(self):
        self.store=Store()
        self.bridge=LiveHTTPBridge(self.store,allowed_origin="https://panel.example.net")

    @staticmethod
    def cookie():
        return "other=whatever; cerato_session=new-session"

    def dispatch(self, handler, method=None):
        method=method or ("POST" if handler.path.endswith("/nat/add") else "GET")
        legacy=handler.do_POST if method=="POST" else handler.do_GET
        self.bridge.dispatch(handler,method,legacy)
        return handler

    def test_anonymous_and_legacy_session_cannot_access_network(self):
        for bad in ("","cerato_session=old-password","legacy_session=old-password"):
            request=Handler("/api/status",cookie=bad)
            self.dispatch(request)
            self.assertEqual(request.status,403)
            self.assertEqual(request.calls,[])
            self.assertNotIn("private_key",request.wfile.getvalue().decode())

    def test_user_status_is_redacted_by_server_before_serialization(self):
        self.store.role="user"
        request=Handler("/api/status",cookie=self.cookie())
        self.dispatch(request)
        self.assertEqual(request.status,200)
        self.assertTrue(request.saved["tunnel_active"])
        self.assertNotIn("private_key",request.saved)
        self.assertNotIn("peers",request.saved)
        self.assertNotIn("ip",request.saved)
        self.assertEqual(request.calls,[("legacy-GET","/api/status")])

    def test_user_mutations_denied_before_legacy_calls(self):
        self.store.role="user"
        request=Handler("/api/nat/add",method="POST",cookie=self.cookie(),
                        csrf="ok-csrf",origin="https://panel.example.net")
        self.dispatch(request,"POST")
        self.assertEqual(request.status,403)
        self.assertEqual(request.calls,[])

    def test_admin_write_requires_exact_origin_and_csrf(self):
        for origin, csrf in (("https://evil.example","ok-csrf"),
                             ("","ok-csrf"),
                             ("https://panel.example.net","wrong")):
            request=Handler("/api/nat/add",method="POST",cookie=self.cookie(),
                            csrf=csrf,origin=origin)
            self.dispatch(request,"POST")
            self.assertEqual(request.status,403)
            self.assertEqual(request.calls,[])
        allowed=Handler("/api/nat/add",method="POST",cookie=self.cookie(),
                        csrf="ok-csrf",origin="https://panel.example.net")
        self.dispatch(allowed,"POST")
        self.assertEqual(allowed.saved,{"ok":True})
        self.assertEqual(allowed.calls,[("legacy-POST","/api/nat/add")])
        self.assertFalse(allowed.check_session(write=True))

    def test_unauthorized_route_is_rejected_before_old_backend(self):
        request=Handler("/api/debug/secret",cookie=self.cookie())
        self.dispatch(request)
        self.assertEqual(request.status,403)
        self.assertEqual(request.calls,[])

    def test_login_requires_password_then_totp(self):
        import json
        body=json.dumps({"email":"owner@example.net","password":"valid-password"}).encode()
        request=Handler("/api/auth/login",method="POST",origin="https://panel.example.net",payload=body)
        self.dispatch(request,"POST")
        self.assertEqual(request.status,200)
        self.assertNotIn("Set-Cookie",request.output_headers)
        self.assertIn(b"mfa_required",request.wfile.getvalue())
        payload=json.dumps({"challenge":"pending","code":"123456"}).encode()
        request=Handler("/api/auth/mfa/verify",method="POST",origin="https://panel.example.net",payload=payload)
        self.dispatch(request,"POST")
        self.assertEqual(request.status,200)
        self.assertIn("HttpOnly",request.output_headers["Set-Cookie"])
        self.assertIn("SameSite=Strict",request.output_headers["Set-Cookie"])

    def test_legacy_login_is_retired(self):
        request=Handler("/api/login",method="POST",origin="https://panel.example.net")
        self.dispatch(request,"POST")
        self.assertEqual(request.status,410)
        self.assertEqual(request.calls,[])

    def test_wrong_host_rejected_prior_to_session(self):
        request=Handler("/api/status",cookie=self.cookie(),host="attacker.invalid")
        self.dispatch(request)
        self.assertEqual(request.status,403)
        self.assertEqual(self.store.checked,[])

    def test_unsafe_json_rejected(self):
        for content,media in ((b'nope',"application/json"),
                              (b'{"key":"value"}',"text/plain")):
            request=Handler("/api/auth/login",method="POST",origin="https://panel.example.net",
                            payload=content,content_type=media)
            self.dispatch(request,"POST")
            self.assertEqual(request.status,400)

    def test_static_routes_keep_existing_behavior(self):
        request=Handler("/")
        self.dispatch(request)
        self.assertEqual(request.calls,[("legacy-GET","/"),("legacy-session",False)])

    def test_wrapper_refuses_class_without_legacy_auth_hook(self):
        class Missing:
            def do_GET(self):pass
            def do_POST(self):pass
        with self.assertRaises(LiveBridgeError):
            wrap_legacy_handler(Missing,self.store,allowed_origin="https://panel.example.net")

    def test_wrapper_is_not_installed_twice(self):
        class Existing(Handler):pass
        wrap_legacy_handler(Existing,self.store,allowed_origin="https://panel.example.net")
        with self.assertRaises(LiveBridgeError):
            wrap_legacy_handler(Existing,self.store,allowed_origin="https://panel.example.net")
        request=Existing("/api/status",cookie=self.cookie())
        request.do_GET()
        self.assertEqual(request.status,200)
        self.assertTrue(request.saved["tunnel_active"])

if __name__=="__main__":
    unittest.main()

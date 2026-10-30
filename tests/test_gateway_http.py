"""Black-box HTTP tests: initial owner, login, CSRF, viewer and owner protection.

Runs only on localhost with temporary test databases. No privileged network
commands, production service changes or public socket exposure.
"""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "security"))
from auth_store import AuthStore
from mfa import code_for_counter

class GatewayHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="cerato-http-test-")
        cls.root = Path(cls.tmp.name)
        cls.db = cls.root / "private" / "accounts.sqlite3"
        cls.bootstrap = AuthStore(cls.db).issue_bootstrap_token()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1",0))
            cls.port = s.getsockname()[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env.update(CERATO_DEV_AUTH_ONLY="1", CERATO_DEV_LOOPBACK_HTTP="1",
                   CERATO_AUTH_DB=str(cls.db), CERATO_PORT=str(cls.port),
                   CERATO_WEB_ORIGIN="https://network.example.org")
        cls.proc = subprocess.Popen([sys.executable,str(ROOT / "gateway" / "http_api.py")],
                                    cwd=str(ROOT),env=env,
                                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(60):
            if cls.proc.poll() is not None:
                raise RuntimeError("Gateway de test a quitté prématurément")
            try:
                status,_,_=cls.request("GET","/api/auth/setup-status")
                if status==200:
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Gateway de test n'écoute pas sur localhost")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait(timeout=3)
        cls.tmp.cleanup()

    @classmethod
    def request(cls,method,path,payload=None, cookie="", csrf="", origin=None):
        conn=http.client.HTTPConnection("127.0.0.1",cls.port,timeout=4)
        headers={"Host":f"127.0.0.1:{cls.port}", "Accept":"application/json"}
        if method not in ("GET","HEAD"):
            headers["Origin"] = cls.origin if origin is None else origin
            headers["Content-Type"] = "application/json"
        if csrf: headers["X-Cerato-CSRF"] = csrf
        if cookie: headers["Cookie"] = cookie
        raw=json.dumps(payload if payload is not None else {}).encode()
        try:
            conn.request(method,path,body=raw if method not in ("GET","HEAD") else None,
                         headers=headers)
            res=conn.getresponse()
            data=res.read()
            return res.status, json.loads(data), dict(res.getheaders())
        finally:
            conn.close()

    def test_full_account_lifecycle(self):
        status, body, _ = self.request("GET","/api/auth/setup-status")
        self.assertEqual(status,200)
        self.assertFalse(body["initialized"])
        status,_,_ = self.request("GET","/api/status")
        self.assertEqual(status,401)

        status,body,_ = self.request("POST","/api/auth/setup",{
            "email":"Owner@Example.org","password":"temporary-owner-password-123",
            "token":self.bootstrap})
        self.assertEqual(status,201,body)
        owner_id=body["account"]["id"]
        self.assertEqual(body["account"]["role"],"owner")
        status,_,_ = self.request("POST","/api/auth/setup",{
            "email":"evil@example.org","password":"temporary-owner-password-123",
            "token":self.bootstrap})
        self.assertEqual(status,403)

        status,body,headers = self.request("POST","/api/auth/login",{
            "email":"owner@example.org","password":"temporary-owner-password-123"})
        self.assertEqual(status,200,body)
        self.assertTrue(body["mfa_required"])
        self.assertNotIn("Set-Cookie", headers)  # Password alone grants no privileged session.
        status,_,_ = self.request("GET","/api/accounts")
        self.assertEqual(status,401)
        status,body,headers = self.request("POST","/api/auth/mfa/verify",{
            "challenge":body["challenge"],
            "code":code_for_counter(body["otp_secret"],int(time.time())//30)})
        self.assertEqual(status,200,body)
        self.assertEqual(len(body["recovery_codes"]),8)
        owner_cookie=headers["Set-Cookie"].split(";",1)[0]
        owner_csrf=body["csrf"]

        status,_,_ = self.request("POST","/api/accounts",{
            "email":"viewer@example.org","password":"read-only-password-123","role":"user"},
            cookie=owner_cookie)
        self.assertEqual(status,403)  # CSRF must be mandatory

        status,body,_ = self.request("POST","/api/accounts",{
            "email":"viewer@example.org","password":"read-only-password-123","role":"user"},
            cookie=owner_cookie, csrf=owner_csrf)
        self.assertEqual(status,201,body)
        self.assertEqual(body["account"]["role"],"user")

        status,body,_ = self.request("PATCH",f"/api/accounts/{owner_id}",{
            "email":"hijacked@example.org"},
            cookie=owner_cookie, csrf=owner_csrf)
        self.assertEqual(status,403)

        status,body,headers = self.request("POST","/api/auth/login",{
            "email":"viewer@example.org","password":"read-only-password-123"})
        self.assertEqual(status,200,body)
        viewer_cookie=headers["Set-Cookie"].split(";",1)[0]
        viewer_csrf=body["csrf"]

        status,body,_ = self.request("GET","/api/status",cookie=viewer_cookie)
        self.assertEqual(status,200,body)
        for sensitive in ("peers","gateway_public_key","pool","wan_ips","publications"):
            self.assertNotIn(sensitive,body)
        status,_,_ = self.request("GET","/api/accounts",cookie=viewer_cookie)
        self.assertEqual(status,403)
        status,_,_ = self.request("POST","/api/updates/install",{},
                                  cookie=viewer_cookie,csrf=viewer_csrf)
        self.assertEqual(status,403)
        status,_,_ = self.request("POST","/api/auth/logout",{},
                                  cookie=viewer_cookie,csrf=viewer_csrf)
        self.assertEqual(status,200)
        status,_,_ = self.request("GET","/api/status",cookie=viewer_cookie)
        self.assertEqual(status,401)

    def test_forbid_cross_origin_requests(self):
        status,_,_ = self.request("POST","/api/auth/login",
            {"email":"x@example.org","password":"no"},
            origin="https://attacker.example.org")
        self.assertEqual(status,403)


if __name__ == "__main__":
    unittest.main()

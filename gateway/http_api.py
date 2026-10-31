#!/usr/bin/env python3
"""Standalone Cerato Network development gateway (account + read-only network status).

This can run next to the existing gateway during development, but NOT on the same
port. Network modifications and agent update API are intentionally disabled
until the legacy ceratoctl adapter and two-factor authentication are audited.
"""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "security"))
from auth_store import AuthStore, AuthError, Forbidden, InvalidCredentials, secure_cookie, viewer_projection
from access_policy import authorize, required_permission
sys.path.insert(0, str(ROOT / 'updates'))
from catalog import configured_info
from installer import stage as stage_signed_release, StageError

BIND = "127.0.0.1"
PORT = int(os.environ.get("CERATO_PORT", "8788"))
ORIGIN = os.environ.get("CERATO_WEB_ORIGIN", "https://network.example.org").rstrip("/")
DATABASE = Path(os.environ.get("CERATO_AUTH_DB", "/var/lib/cerato-network-auth/accounts.sqlite3"))
CTL = os.environ.get("CERATOCTL_BIN", "/usr/local/sbin/ceratoctl")
WEB = ROOT / "web"
MAX_REQUEST = 8192
ALLOWED_MUTATIONS = {
    ("PATCH", "/api/auth/me"), ("POST", "/api/auth/logout"),
    ("POST", "/api/accounts"),
}
STORE = None


class BadRequest(Exception):
    pass


def origin_ok(header: str) -> bool:
    if header == ORIGIN:
        return True
    # Explicit loopback-only allowance to test without an HTTPS reverse proxy.
    # Never enable this flag on a publicly exposed server.
    return (os.environ.get("CERATO_DEV_LOOPBACK_HTTP") == "1" and
            header in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"))


def status_payload():
    if not os.path.isabs(CTL) or not os.path.isfile(CTL):
        return {"dashboard_mode": "unavailable", "tunnel_active": False,
                "peers": {}, "reason": "Moteur réseau non raccordé"}
    try:
        p = subprocess.run(["sudo", "-n", CTL, "status"], capture_output=True,
                           text=True, timeout=8, check=False)
        if p.returncode:
            raise OSError("ceratoctl indisponible")
        data = json.loads(p.stdout)
        if not isinstance(data, dict):
            raise ValueError("État réseau invalide")
        peers = {}
        for name, peer in (data.get("peers") or {}).items():
            if not isinstance(peer, dict) or not isinstance(name, str):
                continue
            peers[name] = {k: peer.get(k) for k in (
                "ip", "pubkey", "last_handshake", "received", "sent", "agent_version",
                "os", "os_version") if k in peer}
        result = {k: data.get(k) for k in (
            "wan_if", "wg_if", "wan_ips", "pool", "wg_port", "gateway_tunnel_ip",
            "gateway_public_key", "publications") if k in data}
        # No 'wg show dump': it may reveal the gateway interface private
        # key. Dedicated read-only sudo privileges permit only these views.
        tunnel_active = False
        try:
            wg_binary = os.environ.get("CERATO_WG_BIN", "/usr/bin/wg")
            wg_iface = str(data.get("wg_if", "wg-cerato"))
            if wg_iface != "wg-cerato":
                raise ValueError("WireGuard interface not authorized in this preview")
            handshake = subprocess.run(
                ["sudo", "-n", wg_binary, "show", wg_iface, "latest-handshakes"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if handshake.returncode == 0:
                tunnel_active = True
                latest = {}
                for line in handshake.stdout.strip().splitlines():
                    fields = line.split("\t")
                    if len(fields) == 2:
                        latest[fields[0]] = int(fields[1])
                transfer = subprocess.run(
                    ["sudo", "-n", wg_binary, "show", wg_iface, "transfer"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                counters = {}
                if transfer.returncode == 0:
                    for line in transfer.stdout.strip().splitlines():
                        fields = line.split("\t")
                        if len(fields) == 3:
                            counters[fields[0]] = (int(fields[1]), int(fields[2]))
                for peer in peers.values():
                    key = peer.get("pubkey")
                    if key in latest:
                        peer["last_handshake"] = latest[key]
                    if key in counters:
                        peer["received"], peer["sent"] = counters[key]
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, IndexError):
            pass
        result.update(peers=peers, tunnel_active=tunnel_active,
                      dashboard_mode="live")
        return result
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        return {"dashboard_mode": "unavailable", "tunnel_active": False,
                "peers": {}, "reason": "Mesures indisponibles"}


class Handler(BaseHTTPRequestHandler):
    server_version = "CeratoNetwork/0.0-dev"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Never log the request body, session cookie, account, password or token.
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def common_headers(self, status, kind="application/json", cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", kind + ("; charset=utf-8" if kind.startswith("text/") or kind == "application/json" else ""))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)

    def json(self, status, obj, cookie=None):
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.common_headers(status, cookie=cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def error(self, status, message):
        return self.json(status, {"error": message})

    def host_ok(self):
        host = self.headers.get("Host", "").lower().strip()
        expected = urlsplit(ORIGIN).netloc.lower()
        return host in {expected, "127.0.0.1:%d" % PORT, "localhost:%d" % PORT}

    def remote_ip(self):
        """Use only Nginx-overwritten X-Real-IP from a trusted local proxy.

        NEVER trust X-Forwarded-For supplied by the browser; without explicit
        opt-in, treat the loopback proxy as the source and limit per account.
        """
        source=self.client_address[0]
        if (os.environ.get("CERATO_TRUST_LOCAL_PROXY") == "1" and
            source in ("127.0.0.1","::1")):
            header=self.headers.get("X-Real-IP","")
            if len(header) <= 64:
                try:
                    return str(ipaddress.ip_address(header))
                except ValueError:
                    pass
        return source

    def token(self):
        try:
            jar = cookies.SimpleCookie()
            jar.load(self.headers.get("Cookie", ""))
            return jar["cerato_session"].value
        except (KeyError, cookies.CookieError):
            return ""

    def read_json(self):
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise BadRequest("Content-Type application/json obligatoire.")
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise BadRequest("Longueur du corps invalide.") from exc
        if size < 2 or size > MAX_REQUEST:
            raise BadRequest("Corps de requête trop volumineux ou absent.")
        try:
            obj = json.loads(self.rfile.read(size))
            if not isinstance(obj, dict):
                raise ValueError()
            return obj
        except (UnicodeError, ValueError):
            raise BadRequest("JSON invalide.")

    def actor(self, method, path):
        csrf = self.headers.get("X-Cerato-CSRF", "")
        return authorize(STORE, self.token(), method, path, csrf=csrf)

    @staticmethod
    def session_cookie(token: str) -> str:
        cookie = secure_cookie(token)
        if os.environ.get("CERATO_DEV_LOOPBACK_HTTP") == "1":
            cookie = cookie.replace("; Secure;", ";")
        return cookie

    @staticmethod
    def expired_cookie() -> str:
        attrs = "Secure; " if os.environ.get("CERATO_DEV_LOOPBACK_HTTP") != "1" else ""
        return "cerato_session=; " + attrs + "HttpOnly; SameSite=Strict; Path=/; Max-Age=0"

    def do_GET(self):
        if not self.host_ok():
            return self.error(403, "Hôte non autorisé.")
        path = urlsplit(self.path).path
        if not path.startswith("/api/"):
            paths = {"/": "index.html", "/index.html": "index.html",
                     "/app.js": "app.js", "/style.css": "style.css"}
            if path not in paths:
                return self.error(404, "Page inexistante.")
            file = WEB / paths[path]
            try:
                data = file.read_bytes()
            except OSError:
                return self.error(404, "Interface non installée.")
            kind = "text/html" if file.suffix == ".html" else ("text/css" if file.suffix == ".css" else "text/javascript")
            self.common_headers(200, kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/auth/setup-status":
            return self.json(200, {"initialized": STORE.is_initialized()})
        try:
            actor = self.actor("GET", path)
            if path == "/api/auth/me":
                return self.json(200, {"account": actor, "csrf": STORE.rotate_csrf(self.token())})
            if path == "/api/status":
                raw = status_payload()
                return self.json(200, raw if actor["role"] != "user" else viewer_projection(raw))
            if path == "/api/accounts":
                return self.json(200, {"accounts": STORE.list_accounts(actor)})
            if path == "/api/updates":
                catalog = configured_info()
                catalog["staging_enabled"] = os.environ.get("CERATO_DEV_STAGE_ENABLED") == "1"
                return self.json(200, catalog)
            return self.error(501, "Fonction non disponible dans cette version.")
        except Forbidden:
            return self.error(403, "Accès refusé.")
        except InvalidCredentials:
            return self.error(401, "Session expirée.")
        except AuthError:
            return self.error(422, "Requête refusée.")

    def do_POST(self):
        return self.mutate("POST")

    def do_PATCH(self):
        return self.mutate("PATCH")

    def do_DELETE(self):
        return self.mutate("DELETE")

    def mutate(self, method):
        if not self.host_ok():
            return self.error(403, "Hôte non autorisé.")
        if not origin_ok(self.headers.get("Origin", "")):
            return self.error(403, "Origine non autorisée.")
        path = urlsplit(self.path).path
        try:
            body = self.read_json()
            if method == "POST" and path == "/api/auth/setup":
                account = STORE.setup_owner(str(body.get("token", "")),
                                            body.get("email"), body.get("password"))
                return self.json(201, {"account": account})
            if method == "POST" and path == "/api/auth/login":
                session = STORE.login(body.get("email"), body.get("password"),
                                      self.remote_ip())
                if session.get("mfa_required"):
                    return self.json(200, session)
                token = session.pop("session")
                csrf = session.pop("csrf")
                return self.json(200, {"account": session["account"], "csrf": csrf},
                                 cookie=self.session_cookie(token))
            if method == "POST" and path == "/api/auth/mfa/verify":
                session = STORE.complete_mfa(body.get("challenge"), body.get("code"))
                token = session.pop("session")
                csrf = session.pop("csrf")
                payload = {"account": session["account"], "csrf": csrf}
                if "recovery_codes" in session:
                    payload["recovery_codes"] = session["recovery_codes"]
                return self.json(200, payload, cookie=self.session_cookie(token))
            actor = self.actor(method, path)
            if method == "POST" and path == "/api/updates/check":
                catalog = configured_info()
                catalog["staging_enabled"] = os.environ.get("CERATO_DEV_STAGE_ENABLED") == "1"
                return self.json(200, catalog)
            if method == "POST" and path == "/api/updates/stage":
                if os.environ.get("CERATO_DEV_STAGE_ENABLED") != "1":
                    return self.error(403, "Préparation de releases désactivée.")
                catalog = configured_info()
                if not catalog.get("verified"):
                    return self.error(422, "Aucune release signée vérifiée.")
                release_dir = os.environ.get("CERATO_RELEASE_DIR", "")
                public_key = os.environ.get("CERATO_RELEASE_PUBKEY", "")
                staging_root = os.environ.get("CERATO_DEV_STAGE_ROOT", "")
                if not release_dir or not public_key or not staging_root:
                    return self.error(422, "Répertoires de test non configurés.")
                info = stage_signed_release(Path(release_dir), Path(public_key), Path(staging_root))
                return self.json(200, info)
            if method == "POST" and path == "/api/auth/logout":
                STORE.logout(self.token())
                return self.json(200, {"ok": True},
                                 cookie=self.expired_cookie())
            if method == "PATCH" and path == "/api/auth/me":
                profile = STORE.change_own_identity(
                    actor, body.get("current_password"),
                    email=body.get("email"), new_password=body.get("new_password"))
                return self.json(200, {"account": profile, "reauth_required": True},
                                 cookie="cerato_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            if method == "POST" and path == "/api/accounts":
                created = STORE.create_account(actor, body.get("email"), body.get("password"),
                                               body.get("role"))
                return self.json(201, {"account": created})
            match = re.fullmatch(r"/api/accounts/(\d+)", path)
            if match:
                target = int(match.group(1))
                if method == "PATCH":
                    fields = {k: body[k] for k in ("email", "role", "active", "new_password", "reset_mfa") if k in body}
                    return self.json(200, {"account": STORE.manage_account(actor, target, **fields)})
                if method == "DELETE":
                    STORE.delete_account(actor, target)
                    return self.json(200, {"ok": True})
            # Deliberately never invoke privileged network commands or shell from
            # generic development authentication HTTP server.
            return self.error(501, "Action réseau / mise à jour désactivée.")
        except BadRequest as exc:
            return self.error(400, str(exc))
        except InvalidCredentials:
            return self.error(401, "Identifiants incorrects ou session expirée.")
        except Forbidden:
            return self.error(403, "Accès refusé.")
        except (AuthError, ValueError, TypeError, StageError):
            return self.error(422, "Valeur invalide ou release refusée.")
        except Exception:
            self.log_error("Erreur interne masquée")
            return self.error(500, "Erreur interne.")


def main():
    global STORE
    if os.environ.get("CERATO_DEV_AUTH_ONLY") != "1":
        sys.exit("Serveur de développement : exiger CERATO_DEV_AUTH_ONLY=1. Ne pas déployer en production.")
    if not (ORIGIN.startswith("https://") and urlsplit(ORIGIN).hostname):
        sys.exit("CERATO_WEB_ORIGIN doit être une origine HTTPS valide.")
    if PORT < 1024 or PORT > 65535:
        sys.exit("Port non autorisé.")
    STORE = AuthStore(DATABASE)
    print(f"Cerato Network DEV: http://{BIND}:{PORT}", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

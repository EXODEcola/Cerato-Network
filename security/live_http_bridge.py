"""In-process HTTP authorization bridge for the historical RISE-1 console.

Prepared for a later *reviewed* cutover. It does not replace the existing
network handlers. It is intentionally NOT loaded by the production service.

Security invariant: every /api/ request first passes through AuthStore and
explicit RBAC; an existing legacy cookie/password cannot authorize it.
"""
from __future__ import annotations

from http import cookies
import json
from urllib.parse import urlsplit

from auth_store import AuthError, Forbidden, InvalidCredentials
from legacy_auth_api import LegacyAuthAPI
from live_session_guard import authorize_legacy_request, project_legacy_status

MAX_JSON = 8192
ACCOUNT_PREFIX = "/api/auth/"
LEGACY_LOGIN = frozenset({"/api/login", "/api/logout"})


class LiveBridgeError(RuntimeError):
    pass


def _cookie(raw) -> str:
    if not isinstance(raw, str) or len(raw) > 8192:
        return ""
    try:
        jar = cookies.SimpleCookie()
        jar.load(raw)
        return jar["cerato_session"].value
    except (KeyError, cookies.CookieError, ValueError):
        return ""


def _json_body(handler):
    raw_length = handler.headers.get("Content-Length", "")
    media = handler.headers.get("Content-Type", "").split(";", 1)[0].lower().strip()
    if media != "application/json" or not raw_length.isdecimal():
        raise Forbidden("Requête JSON invalide")
    length = int(raw_length)
    if not 2 <= length <= MAX_JSON:
        raise Forbidden("Taille JSON invalide")
    try:
        body = json.loads(handler.rfile.read(length))
    except (ValueError, UnicodeError):
        raise Forbidden("JSON invalide") from None
    if not isinstance(body, dict):
        raise Forbidden("Objet JSON requis")
    return body


def _reply(handler, code, payload, cookie=None):
    """Own only auth responses; never forward token/cookie to legacy handlers."""
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    if cookie is not None:
        handler.send_header("Set-Cookie", cookie)
    handler.end_headers()
    handler.wfile.write(encoded)


class LiveHTTPBridge:
    """Wrap GET/POST/PATCH/DELETE only after an audited legacy handler review.

    The trusted reverse proxy MUST preserve Host, Origin, Cookie, and CSRF,
    and MUST limit the backend to loopback. A new auth frontend is required
    before removing HTTP Basic. Not a drop-in production installer.
    """

    def __init__(self, store, *, allowed_origin: str):
        self.store = store
        self.api = LegacyAuthAPI(store, allowed_origin=allowed_origin)
        self.origin = allowed_origin.rstrip("/")
        self.hostname = urlsplit(self.origin).netloc.lower()

    def dispatch(self, handler, method: str, legacy_method):
        method = method.upper()
        path = urlsplit(handler.path).path
        if not path.startswith("/api/"):
            return legacy_method()

        # Do not trust proxy-provided host aliases for browser-facing auth.
        if handler.headers.get("Host", "").lower().strip() != self.hostname:
            return _reply(handler, 403, {"error": "Hôte non autorisé."})
        token = _cookie(handler.headers.get("Cookie", ""))
        origin = handler.headers.get("Origin", "")
        csrf = handler.headers.get("X-Cerato-CSRF", "")
        if method not in {"GET", "HEAD"} and origin != self.origin:
            return _reply(handler, 403, {"error": "Origine non autorisée."})
        if len(csrf) > 256:
            return _reply(handler, 403, {"error": "CSRF invalide."})

        if (path.startswith(ACCOUNT_PREFIX) or path.startswith("/api/accounts")
                or path in LEGACY_LOGIN):
            try:
                body = _json_body(handler) if method not in {"GET", "HEAD"} else {}
            except Forbidden:
                return _reply(handler, 400, {"error": "Requête invalide."})
            response = self.api.handle(
                method, path, body=body, session=token, csrf=csrf, origin=origin,
                source_ip=handler.client_address[0] if handler.client_address else "",
            )
            if response is None:
                return _reply(handler, 404, {"error": "Route inconnue."})
            return _reply(handler, response.code, response.payload, response.cookie)

        # Critical: every existing network route is authorized before its
        # handler can read a body or invoke ceratoctl/nft/WireGuard.
        try:
            actor = authorize_legacy_request(self.store, token, method, path, csrf)
        except (AuthError, ValueError, TypeError):
            return _reply(handler, 403, {"error": "Session ou autorisation refusée."})
        # Existing internal check_session() still expects the obsolete password.
        # A request-local bypass is safe ONLY after the new session/RBAC/CSRF gate.
        # Never override global process state or other handler instances.
        previous = getattr(handler, "check_session", None)
        if not callable(previous):
            raise LiveBridgeError("Legacy session hook missing")
        handler.check_session = lambda *args, **kwargs: True
        prior_send = getattr(handler, "send_json", None)
        try:
            if actor["role"] == "user":
                if method != "GET" or path != "/api/status" or not callable(prior_send):
                    raise LiveBridgeError("Projection en lecture seule non sûre")
                def projected(status, payload, *args, **kwargs):
                    safe = project_legacy_status(actor, payload)
                    return prior_send(status, safe, *args, **kwargs)
                handler.send_json = projected
            return legacy_method()
        finally:
            handler.check_session = previous
            if actor["role"] == "user":
                handler.send_json = prior_send


def wrap_legacy_handler(handler_class, store, *, allowed_origin: str):
    """Modify only a class passed explicitly by a controlled staging harness."""
    bridge = LiveHTTPBridge(store, allowed_origin=allowed_origin)
    if getattr(handler_class, "_cerato_live_bridge_installed", False):
        raise LiveBridgeError("Bridge already installed")
    if not callable(getattr(handler_class, "check_session", None)):
        raise LiveBridgeError("Legacy class has no session hook")
    for verb in ("GET", "POST"):
        name = "do_" + verb
        old = getattr(handler_class, name, None)
        if not callable(old):
            raise LiveBridgeError("Legacy HTTP handler lacks " + name)
    for verb in ("GET", "POST", "PATCH", "DELETE"):
        name = "do_" + verb
        old = getattr(handler_class, name, None)
        if old is None:
            continue
        def gated(self, _method=old, _verb=verb):
            return bridge.dispatch(self, _verb, lambda: _method(self))
        setattr(handler_class, name, gated)
    handler_class._cerato_live_bridge_installed = True
    return handler_class

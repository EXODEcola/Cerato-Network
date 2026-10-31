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

    def __init__(self, store, *, allowed_origin: str, viewer_status_provider=None):
        self.store = store
        self.api = LegacyAuthAPI(store, allowed_origin=allowed_origin)
        self.origin = allowed_origin.rstrip("/")
        self.hostname = urlsplit(self.origin).netloc.lower()
        # Explicit trusted data provider: a viewer NEVER reaches legacy
        # serialization functions that may bypass send_json() entirely.
        self.viewer_status_provider = viewer_status_provider

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
        # A viewer never executes any historical route or serializer:
        # legacy code could call send_error(), _json() or write() directly,
        # bypassing a simple send_json() projection wrapper.
        if actor["role"] == "user":
            if method != "GET" or path != "/api/status" or not callable(self.viewer_status_provider):
                return _reply(handler, 403, {"error": "Projection en lecture seule indisponible."})
            try:
                safe = project_legacy_status(actor, self.viewer_status_provider())
            except (AuthError, ValueError, TypeError, KeyError):
                return _reply(handler, 503, {"error": "État de consultation indisponible."})
            return _reply(handler, 200, safe)
        # Owners and administrators have passed session, RBAC and CSRF.
        # The old check_session() still expects an obsolete password, so
        # bypass it for THIS request only (not globally).
        previous = getattr(handler, "check_session", None)
        if not callable(previous):
            raise LiveBridgeError("Legacy session hook missing")
        handler.check_session = lambda *args, **kwargs: True
        try:
            return legacy_method()
        finally:
            handler.check_session = previous


def wrap_legacy_handler(handler_class, store, *, allowed_origin: str,
                        viewer_status_provider=None):
    """Modify only a class passed explicitly by a controlled staging harness."""
    bridge = LiveHTTPBridge(store, allowed_origin=allowed_origin,
                            viewer_status_provider=viewer_status_provider)
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
            # The real OVH legacy handler implements only GET/POST. Native
            # account/profile mutations require PATCH/DELETE, so provide
            # these verbs without forwarding them to any legacy operation.
            # All non-account routes still fail closed in dispatch().
            def unavailable(self):
                return _reply(self, 405, {"error": "Méthode historique interdite."})
            old = unavailable
        def gated(self, _method=old, _verb=verb):
            return bridge.dispatch(self, _verb, lambda: _method(self))
        setattr(handler_class, name, gated)
    handler_class._cerato_live_bridge_installed = True
    return handler_class

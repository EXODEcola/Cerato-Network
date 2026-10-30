"""Fail-closed API permissions for Cerato Network.

All existing privileged operations must be checked with this allowlist before
they reach ceratoctl, sudo, package update services or state mutation.
"""

from auth_store import Forbidden

# Routes with no HTTP session, subject to rate limit / one-time setup token.
PUBLIC = {
    ("GET", "/api/auth/setup-status"),
    ("POST", "/api/auth/setup"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/mfa/verify"),
}

EXACT = {
    ("GET", "/api/auth/me"): "view",
    ("PATCH", "/api/auth/me"): "view",
    ("POST", "/api/auth/logout"): "view",
    ("GET", "/api/status"): "view",
    ("GET", "/api/session"): "view",
    ("GET", "/api/events"): "view_sensitive",
    ("GET", "/api/nft-preview"): "view_sensitive",
    ("GET", "/api/wg-config"): "view_sensitive",
    ("GET", "/api/accounts"): "accounts_manage",
    ("POST", "/api/accounts"): "accounts_manage",
    ("POST", "/api/enroll/token"): "network_write",
    ("POST", "/api/peers"): "network_write",
    ("POST", "/api/peers/remove"): "network_write",
    ("POST", "/api/ip/add"): "network_write",
    ("POST", "/api/ip/remove"): "network_write",
    ("POST", "/api/nat/add"): "network_write",
    ("POST", "/api/nat/remove"): "network_write",
    ("GET", "/api/updates"): "updates_manage",
    ("POST", "/api/updates/check"): "updates_manage",
    ("POST", "/api/updates/stage"): "updates_manage",
    ("POST", "/api/updates/install"): "updates_manage",
    ("POST", "/api/updates/rollback"): "updates_manage",
}


def required_permission(method: str, path: str):
    """Return required permission, None if public, raise for unknown endpoints."""
    method = method.upper()
    path = path.split("?", 1)[0]
    pair = (method, path)
    if pair in PUBLIC:
        return None
    if pair in EXACT:
        return EXACT[pair]
    components = path.strip("/").split("/")
    if len(components) == 3 and components[:2] == ["api", "accounts"] and components[2].isdigit():
        if method in {"GET","PATCH","DELETE"}:
            return "accounts_manage"
    raise Forbidden("Endpoint API non autorisé.")


def authorize(store, session_token: str, method: str, path: str, csrf: str | None = None):
    permission = required_permission(method, path)
    if permission is None:
        return None
    actor = store.actor(session_token)
    store.require_permission(actor, permission)
    if method.upper() not in {"GET","HEAD","OPTIONS"}:
        store.verify_csrf(session_token, csrf)
    return actor

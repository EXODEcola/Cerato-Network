"""Fail-closed session/CSRF adapter for reviewed legacy HTTP routes.

Pure integration point: no live handler is modified here. The deployed 8787
server must invoke this BEFORE any legacy ceratoctl, ipctl, update or NAT work.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from auth_store import Forbidden, viewer_projection
from legacy_policy import allow, privilege

LEGACY_SESSION_ENDPOINTS = frozenset({'/api/login', '/api/logout'})


def authorize_legacy_request(store, session_token, method, path, csrf_token=None):
    """Validate session, role and CSRF before a reviewed legacy API action.

    Caller must extract session from a secure cookie (never URL/query/body),
    validate same-origin requests, and call this before any backend work.
    Only new /api/auth/* handlers may create account sessions.
    """
    if not isinstance(method, str) or not isinstance(path, str):
        raise Forbidden('Requête non autorisée')
    route = urlsplit(path).path
    if route in LEGACY_SESSION_ENDPOINTS:
        raise Forbidden('Ancienne authentification désactivée')
    permission = privilege(method, route)
    if permission == 'public':
        raise Forbidden('Route publique réservée à l’authentification moderne')
    actor = store.actor(session_token)
    allow(method, route, actor)
    store.require_permission(actor, permission)
    if method.upper() not in {'GET', 'HEAD', 'OPTIONS'}:
        store.verify_csrf(session_token, csrf_token)
    return actor


def project_legacy_status(actor, payload):
    """Redact status inside the server before JSON serialization to viewers."""
    if not isinstance(actor, dict) or actor.get('role') not in {'owner', 'admin', 'user'}:
        raise Forbidden('Session requise')
    if not isinstance(payload, dict):
        raise Forbidden('Statut invalide')
    return viewer_projection(payload) if actor['role'] == 'user' else payload

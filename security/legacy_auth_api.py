"""Framework-neutral HTTP adapter for the RISE-1 account routes.

The caller supplies trusted client IP, real Origin and session cookie values,
and serializes AuthReply with Cache-Control: no-store. This adapter NEVER
executes network commands and is NOT enabled in the live 8787 service.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

from auth_store import AuthError, Forbidden, InvalidCredentials, secure_cookie

_ACCOUNT_PATH = re.compile(r"^/api/accounts/([1-9][0-9]{0,10})$")
_AUTH_PATHS = frozenset({
    "/api/auth/setup-status", "/api/auth/setup", "/api/auth/login",
    "/api/auth/mfa/verify", "/api/auth/me", "/api/auth/logout",
    "/api/accounts",
})


@dataclass(frozen=True)
class AuthReply:
    code: int
    payload: dict
    cookie: str | None = None


def _expired_cookie() -> str:
    return 'cerato_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'


def _object(body: object) -> dict:
    if not isinstance(body, dict):
        raise ValueError('Corps JSON invalide')
    return body


class LegacyAuthAPI:
    """Handle only /api/auth/* and /api/accounts* in a reviewed 8787 handler.

    None means "not an auth endpoint". The caller MUST then check RBAC via
    authorize_legacy_request before executing ANY old network handler.
    """

    def __init__(self, store, *, allowed_origin: str):
        parts = urlsplit(allowed_origin)
        if (parts.scheme != 'https' or not parts.netloc or parts.username or
                parts.password or parts.path not in ('', '/') or parts.query or parts.fragment):
            raise ValueError('Origine HTTPS de confiance requise')
        self.store = store
        self.allowed_origin = allowed_origin.rstrip('/')

    def handle(self, method: str, url: str, *, body=None, session=None,
               csrf=None, origin=None, source_ip=None) -> AuthReply | None:
        method = str(method).upper()
        path = urlsplit(url).path
        if path in {'/api/login', '/api/logout'}:
            return AuthReply(410, {'error': 'Authentification historique désactivée.'})
        if path not in _AUTH_PATHS and not _ACCOUNT_PATH.fullmatch(path):
            return None
        if method not in {'GET', 'POST', 'PATCH', 'DELETE'}:
            return AuthReply(405, {'error': 'Méthode interdite.'})
        try:
            if method in {'POST', 'PATCH', 'DELETE'}:
                if origin != self.allowed_origin:
                    raise Forbidden('Origine de requête invalide')
                data = _object(body)
            else:
                data = {}
            if (method, path) == ('GET', '/api/auth/setup-status'):
                return AuthReply(200, {'initialized': self.store.is_initialized()})
            if (method, path) == ('POST', '/api/auth/setup'):
                account = self.store.setup_owner(data.get('token'), data.get('email'), data.get('password'))
                return AuthReply(201, {'account': account})
            if (method, path) == ('POST', '/api/auth/login'):
                result = self.store.login(data.get('email'), data.get('password'), source_ip or '')
                return self._login_reply(result)
            if (method, path) == ('POST', '/api/auth/mfa/verify'):
                result = self.store.complete_mfa(data.get('challenge'), data.get('code'))
                return self._login_reply(result)
            actor = self.store.actor(session)
            if method != 'GET':
                self.store.verify_csrf(session, csrf)
            if (method, path) == ('GET', '/api/auth/me'):
                return AuthReply(200, {'account': actor, 'csrf': self.store.rotate_csrf(session)})
            if (method, path) == ('PATCH', '/api/auth/me'):
                if not data or set(data) - {'current_password', 'email', 'new_password'}:
                    raise Forbidden('Champs de profil non autorisés')
                account = self.store.change_own_identity(
                    actor, data.get('current_password'),
                    email=data.get('email'), new_password=data.get('new_password'))
                return AuthReply(200, {'account': account, 'reauth_required': True}, _expired_cookie())
            if (method, path) == ('POST', '/api/auth/logout'):
                self.store.logout(session)
                return AuthReply(200, {'ok': True}, _expired_cookie())
            self.store.require_permission(actor, 'accounts_manage')
            if (method, path) == ('GET', '/api/accounts'):
                return AuthReply(200, {'accounts': self.store.list_accounts(actor)})
            if (method, path) == ('POST', '/api/accounts'):
                if set(data) != {'email', 'password', 'role'}:
                    raise Forbidden('Champs de création invalides')
                account = self.store.create_account(
                    actor, data.get('email'), data.get('password'), data.get('role'))
                return AuthReply(201, {'account': account})
            match = _ACCOUNT_PATH.fullmatch(path)
            if match and method == 'PATCH':
                allowed = {'email', 'role', 'active', 'new_password', 'reset_mfa'}
                if not data or set(data) - allowed:
                    raise Forbidden('Champs de gestion invalides')
                fields = {key: data[key] for key in allowed if key in data}
                account = self.store.manage_account(actor, int(match.group(1)), **fields)
                return AuthReply(200, {'account': account})
            if match and method == 'DELETE':
                self.store.delete_account(actor, int(match.group(1)))
                return AuthReply(200, {'ok': True})
            return AuthReply(405, {'error': 'Route ou méthode non autorisée.'})
        except InvalidCredentials:
            return AuthReply(401, {'error': 'Identifiants invalides ou session expirée.'})
        except Forbidden:
            return AuthReply(403, {'error': 'Accès refusé.'})
        except (AuthError, ValueError, TypeError):
            return AuthReply(422, {'error': 'Requête invalide ou refusée.'})

    @staticmethod
    def _login_reply(result: dict) -> AuthReply:
        if result.get('mfa_required'):
            # Seed appears only during initial enrollment; never log response.
            return AuthReply(200, result)
        result = result.copy()
        session = result.pop('session')
        csrf = result.pop('csrf')
        payload = {'account': result['account'], 'csrf': csrf}
        if 'recovery_codes' in result:
            payload['recovery_codes'] = result['recovery_codes']
        return AuthReply(200, payload, secure_cookie(session))

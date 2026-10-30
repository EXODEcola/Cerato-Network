"""Persistent authentication core for Cerato Network.

This module has no HTTP handlers and does NOT modify the running RISE-1 service.
The production gateway must call require_permission() for every endpoint.
Requires argon2-cffi. Do not place the database in a publicly served directory.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

ROLES = ("owner", "admin", "user")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,185}$")
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32)
SESSION_SECONDS = 8 * 3600


class AuthError(Exception):
    pass


class Forbidden(AuthError):
    pass


class InvalidCredentials(AuthError):
    pass


def validate_email(value: str) -> str:
    if not isinstance(value, str):
        raise AuthError("Adresse e-mail incorrecte.")
    result = value.strip().lower()
    if len(result) > 254 or not EMAIL_PATTERN.fullmatch(result) or "." not in result.split("@")[-1]:
        raise AuthError("Adresse e-mail incorrecte.")
    return result


def validate_password(value: str) -> str:
    if not isinstance(value, str) or not 14 <= len(value) <= 1024:
        raise AuthError("Le mot de passe doit contenir entre 14 et 1024 caractères.")
    return value


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _public(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"], "email": row["email"],
        "role": row["role"], "active": bool(row["active"]),
    }


class AuthStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise AuthError("Base d'authentification symbolique refusée.")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _db(self):
        connection = sqlite3.connect(self.path, timeout=8)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=8000")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init(self):
        # The service account must own this directory. Never expose it from Nginx.
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                  passhash TEXT NOT NULL,
                  role TEXT NOT NULL CHECK(role IN ('owner','admin','user')),
                  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                  created_at INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_primary_owner
                  ON accounts(role) WHERE role='owner';
                CREATE TABLE IF NOT EXISTS bootstrap (
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                  tokenhash TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                  tokenhash TEXT PRIMARY KEY, csrfhash TEXT NOT NULL,
                  account_id INTEGER NOT NULL REFERENCES accounts(id),
                  expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS failed_logins (
                  key TEXT PRIMARY KEY, attempts INTEGER NOT NULL,
                  since INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  created_at INTEGER NOT NULL,
                  actor_id INTEGER, action TEXT NOT NULL,
                  target_id INTEGER
                );
            """)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _audit(db, action: str, actor=None, target=None):
        db.execute(
            "INSERT INTO auth_audit(created_at,actor_id,action,target_id) VALUES(?,?,?,?)",
            (int(time.time()), actor, action, target),
        )

    def is_initialized(self) -> bool:
        with self._db() as db:
            return db.execute("SELECT 1 FROM accounts WHERE role='owner'").fetchone() is not None

    def issue_bootstrap_token(self, seconds=900) -> str:
        """Call only from a local SSH-authorized CLI; NEVER expose as an API."""
        if not 60 <= seconds <= 3600:
            raise AuthError("Durée de validité incorrecte.")
        token = secrets.token_urlsafe(36)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM accounts WHERE role='owner'").fetchone():
                raise Forbidden("Le compte principal existe déjà.")
            db.execute(
                "INSERT INTO bootstrap(singleton,tokenhash,expires_at) VALUES(1,?,?) "
                "ON CONFLICT(singleton) DO UPDATE SET tokenhash=excluded.tokenhash,"
                "expires_at=excluded.expires_at",
                (_digest(token), int(time.time()) + seconds),
            )
            self._audit(db, "setup-token-issued")
        return token

    def setup_owner(self, token: str, email: str, password: str) -> dict:
        """Atomic first-run setup: impossible to create a second primary owner."""
        email = validate_email(email)
        password = validate_password(password)
        if not isinstance(token, str) or len(token) > 256:
            raise InvalidCredentials("Code d'initialisation invalide ou expiré.")
        now = int(time.time())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM accounts WHERE role='owner'").fetchone():
                raise Forbidden("Le compte principal existe déjà.")
            row = db.execute("SELECT tokenhash,expires_at FROM bootstrap WHERE singleton=1").fetchone()
            if not row or row["expires_at"] < now or not hmac.compare_digest(row["tokenhash"], _digest(token)):
                raise InvalidCredentials("Code d'initialisation invalide ou expiré.")
            # Only perform expensive Argon2id work AFTER validating the one-time
            # host-secret; otherwise anonymous setup calls are a CPU/memory DoS.
            password_hash = HASHER.hash(password)
            cur = db.execute(
                "INSERT INTO accounts(email,passhash,role,active,created_at) VALUES(?,?,'owner',1,?)",
                (email, password_hash, now),
            )
            db.execute("DELETE FROM bootstrap")
            self._audit(db, "primary-owner-created", cur.lastrowid, cur.lastrowid)
            return {"id": cur.lastrowid, "email": email, "role": "owner", "active": True}

    @staticmethod
    def _failed(db, key: str, now: int):
        row = db.execute("SELECT attempts,since FROM failed_logins WHERE key=?", (key,)).fetchone()
        if not row or now - row["since"] >= 900:
            db.execute("INSERT INTO failed_logins(key,attempts,since) VALUES(?,1,?) "
                       "ON CONFLICT(key) DO UPDATE SET attempts=1,since=excluded.since", (key, now))
        else:
            db.execute("UPDATE failed_logins SET attempts=attempts+1 WHERE key=?", (key,))

    def login(self, email: str, password: str, source_ip: str) -> dict:
        """Returns the raw session and CSRF only once, to place in secure cookies/UI."""
        now = int(time.time())
        try:
            canonical_email = validate_email(email)
        except AuthError:
            canonical_email = "invalid@invalid"
        # Two independent limits, prevents changing emails to bypass the IP limit.
        keys = ("ip:" + _digest(str(source_ip)[:128]), "account:" + _digest(canonical_email))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            for k in keys:
                attempt = db.execute("SELECT attempts,since FROM failed_logins WHERE key=?", (k,)).fetchone()
                if attempt and now - attempt["since"] < 900 and attempt["attempts"] >= 8:
                    raise InvalidCredentials("Identifiants incorrects ou accès temporairement limité.")
            row = db.execute("SELECT * FROM accounts WHERE email=?", (canonical_email,)).fetchone()
            valid = False
            if row and row["active"] and isinstance(password, str):
                try:
                    valid = HASHER.verify(row["passhash"], password)
                except (VerifyMismatchError, VerificationError, InvalidHashError):
                    valid = False
            if not valid:
                for k in keys:
                    self._failed(db, k, now)
                self._audit(db, "login-rejected")
                db.commit()  # Persist rate-limit counters before returning a generic error.
                raise InvalidCredentials("Identifiants incorrects ou accès temporairement limité.")
            for k in keys:
                db.execute("DELETE FROM failed_logins WHERE key=?", (k,))
            token = secrets.token_urlsafe(48)
            csrf = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO sessions(tokenhash,csrfhash,account_id,expires_at) VALUES(?,?,?,?)",
                (_digest(token), _digest(csrf), row["id"], now + SESSION_SECONDS),
            )
            self._audit(db, "login-success", row["id"])
            return {"session": token, "csrf": csrf, "expires_at": now + SESSION_SECONDS,
                    "account": _public(row)}

    def actor(self, session_token: str) -> dict:
        if not isinstance(session_token, str) or not (20 <= len(session_token) <= 256):
            raise InvalidCredentials("Session absente.")
        with self._db() as db:
            row = db.execute(
                "SELECT a.* FROM sessions s JOIN accounts a ON a.id=s.account_id "
                "WHERE s.tokenhash=? AND s.expires_at>? AND a.active=1",
                (_digest(session_token), int(time.time())),
            ).fetchone()
            if not row:
                raise InvalidCredentials("Session expirée.")
            return _public(row)

    def verify_csrf(self, session_token: str, csrf_token: str):
        self.actor(session_token)
        with self._db() as db:
            row = db.execute("SELECT csrfhash FROM sessions WHERE tokenhash=?", (_digest(session_token),)).fetchone()
            if not row or not isinstance(csrf_token, str) or not hmac.compare_digest(row["csrfhash"], _digest(csrf_token)):
                raise Forbidden("Jeton anti-CSRF invalide.")

    def rotate_csrf(self, session_token: str) -> str:
        # Renew a CSRF token from an authenticated, unexpired session.
        self.actor(session_token)
        csrf = secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute("UPDATE sessions SET csrfhash=? WHERE tokenhash=? AND expires_at>?",
                       (_digest(csrf), _digest(session_token), int(time.time())))
        return csrf

    def delete_account(self, actor: dict, target_id: int):
        self.require_permission(actor, "accounts_manage")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT id,role FROM accounts WHERE id=?", (target_id,)).fetchone()
            if not target:
                raise AuthError("Compte inconnu.")
            if target["role"] == "owner" or target["id"] == actor["id"]:
                raise Forbidden("Suppression de ce compte interdite.")
            db.execute("DELETE FROM sessions WHERE account_id=?", (target_id,))
            db.execute("DELETE FROM accounts WHERE id=?", (target_id,))
            self._audit(db, "account-deleted", actor["id"], target_id)

    def logout(self, token: str):
        with self._db() as db:
            db.execute("DELETE FROM sessions WHERE tokenhash=?", (_digest(token),))

    @staticmethod
    def require_permission(actor: dict, permission: str):
        rights = {
            "owner": {"view","view_sensitive","network_write","accounts_manage","updates_manage"},
            "admin": {"view","view_sensitive","network_write","accounts_manage","updates_manage"},
            "user": {"view"},
        }
        if permission not in rights.get(actor.get("role"), set()):
            raise Forbidden("Permission insuffisante.")

    def list_accounts(self, actor: dict) -> list[dict]:
        self.require_permission(actor, "accounts_manage")
        with self._db() as db:
            return [_public(row) for row in db.execute("SELECT id,email,role,active FROM accounts ORDER BY id")]

    def create_account(self, actor: dict, email: str, password: str, role: str) -> dict:
        self.require_permission(actor, "accounts_manage")
        if role not in ("admin", "user"):
            raise Forbidden("Création de propriétaire principal interdite.")
        email, password = validate_email(email), validate_password(password)
        with self._db() as db:
            cur = db.execute(
                "INSERT INTO accounts(email,passhash,role,active,created_at) VALUES(?,?,?,1,?)",
                (email, HASHER.hash(password), role, int(time.time())),
            )
            self._audit(db, "account-created", actor["id"], cur.lastrowid)
            return {"id":cur.lastrowid,"email":email,"role":role,"active":True}

    def manage_account(self, actor: dict, target_id: int, *, email=None, role=None, active=None, new_password=None):
        self.require_permission(actor, "accounts_manage")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT * FROM accounts WHERE id=?", (target_id,)).fetchone()
            if not target:
                raise AuthError("Compte inconnu.")
            if target["role"] == "owner" or target["id"] == actor["id"]:
                raise Forbidden("Le compte principal et votre propre compte ne sont pas modifiables ici.")
            values = {}
            if email is not None:
                values["email"] = validate_email(email)
            if role is not None:
                if role not in ("admin", "user"):
                    raise Forbidden("Rôle propriétaire interdit.")
                values["role"] = role
            if active is not None:
                if not isinstance(active, bool):
                    raise AuthError("État invalide.")
                values["active"] = int(active)
            if new_password is not None:
                values["passhash"] = HASHER.hash(validate_password(new_password))
            if not values:
                return _public(target)
            columns = ",".join(k+"=?" for k in values)
            db.execute("UPDATE accounts SET "+columns+" WHERE id=?", (*values.values(),target_id))
            if "passhash" in values or values.get("active") == 0 or "role" in values or "email" in values:
                db.execute("DELETE FROM sessions WHERE account_id=?", (target_id,))
            self._audit(db, "account-managed", actor["id"], target_id)
            return _public(db.execute("SELECT * FROM accounts WHERE id=?", (target_id,)).fetchone())

    def change_own_identity(self, actor: dict, current_password: str, *, email=None, new_password=None):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM accounts WHERE id=? AND active=1", (actor["id"],)).fetchone()
            if not row:
                raise InvalidCredentials("Compte indisponible.")
            try:
                valid = HASHER.verify(row["passhash"], current_password)
            except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
                valid = False
            if not valid:
                raise InvalidCredentials("Mot de passe actuel incorrect.")
            changes = {}
            if email is not None:
                changes["email"] = validate_email(email)
            if new_password is not None:
                changes["passhash"] = HASHER.hash(validate_password(new_password))
            if not changes:
                raise AuthError("Aucune modification fournie.")
            db.execute("UPDATE accounts SET "+",".join(k+"=?" for k in changes)+" WHERE id=?",
                       (*changes.values(),actor["id"]))
            db.execute("DELETE FROM sessions WHERE account_id=?", (actor["id"],))
            self._audit(db, "self-credentials-changed", actor["id"], actor["id"])
            return _public(db.execute("SELECT * FROM accounts WHERE id=?", (actor["id"],)).fetchone())


def _safe_handshake(value):
    try:
        stamp = int(value)
        return stamp if stamp > 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def _recent_handshake(value):
    stamp = _safe_handshake(value)
    return bool(stamp and 0 <= int(time.time()) - stamp < 180)


def viewer_projection(status: dict) -> dict:
    """Explicit allow-list. NEVER pass through whole backend status to a viewer."""
    peers = status.get("peers") or {}
    items = []
    for name, peer in peers.items():
        if not isinstance(peer, dict):
            continue
        items.append({
            "name": str(name)[:80],
            "connected": _recent_handshake(peer.get("last_handshake")),
            "last_handshake": _safe_handshake(peer.get("last_handshake")),
        })
    return {
        "dashboard_mode": status.get("dashboard_mode"),
        "tunnel_active": bool(status.get("tunnel_active")),
        "machines": items,
        "machine_count": len(items),
        "timestamp": status.get("timestamp"),
    }


def secure_cookie(session_token: str) -> str:
    return "cerato_session=" + session_token + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800"

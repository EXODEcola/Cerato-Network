"""Non-production unit tests for owner/admin/user security boundaries.

Run on the build VPS:
python3 -m pip install argon2-cffi
python3 -m unittest discover -s tests -p 'test_auth_store.py' -v
"""
import sys
import time
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security"))

from auth_store import AuthStore, Forbidden, InvalidCredentials, viewer_projection, secure_cookie
from mfa import code_for_counter


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = AuthStore(Path(self.tmp.name) / "private" / "users.sqlite")
        self.owner = self.store.setup_owner(
            self.store.issue_bootstrap_token(), "Main@Cerato.Test", "owner-secret-password-123"
        )
        self.backup_codes = []

    def _actor(self, email, password):
        session = self.store.login(email, password, "127.0.0.1")
        if session.get("mfa_required"):
            if session["mfa_setup"]:
                secret = session["otp_secret"]
                code = code_for_counter(secret, int(time.time()) // 30)
            else:
                code = self.backup_codes.pop()
            session = self.store.complete_mfa(session["challenge"], code)
            self.backup_codes.extend(session.get("recovery_codes", []))
        return self.store.actor(session["session"]), session

    def test_first_login_sets_owner_email_and_password(self):
        self.assertEqual(self.owner["email"], "main@cerato.test")
        self.assertEqual(self.owner["role"], "owner")
        self.assertTrue(self.store.is_initialized())
        with self.assertRaises(Forbidden):
            self.store.issue_bootstrap_token()

    def test_cannot_create_second_owner(self):
        with self.assertRaises(Forbidden):
            self.store.setup_owner("fake", "other@cerato.test", "other-good-password-123")

    def test_login_session_and_csrf(self):
        first = self.store.login("main@cerato.test", "owner-secret-password-123", "127.0.0.1")
        self.assertTrue(first["mfa_required"])
        self.assertTrue(first["mfa_setup"])
        self.assertNotIn("session", first)
        actor, session = self._actor("main@cerato.test", "owner-secret-password-123")
        self.assertEqual(actor["role"], "owner")
        self.store.verify_csrf(session["session"], session["csrf"])
        with self.assertRaises(Forbidden):
            self.store.verify_csrf(session["session"], "wrong")
        self.store.logout(session["session"])
        with self.assertRaises(InvalidCredentials):
            self.store.actor(session["session"])

    def test_admin_can_manage_another_admin_and_user(self):
        a, _ = self._actor("main@cerato.test", "owner-secret-password-123")
        manager = self.store.create_account(a, "manager@cerato.test", "manager-password-123", "admin")
        other = self.store.create_account(a, "other@cerato.test", "second-admin-password-123", "admin")
        staff = self.store.create_account(a, "staff@cerato.test", "readonly-password-123", "user")
        admin, _ = self._actor("manager@cerato.test", "manager-password-123")
        self.assertEqual(admin["id"], manager["id"])
        self.assertEqual(self.store.manage_account(admin, other["id"], role="user")["role"], "user")
        self.assertFalse(self.store.manage_account(admin, staff["id"], active=False)["active"])

    def test_admin_cannot_touch_primary_owner_or_self(self):
        a, _ = self._actor("main@cerato.test", "owner-secret-password-123")
        manager = self.store.create_account(a, "manager@cerato.test", "manager-password-123", "admin")
        admin, _ = self._actor("manager@cerato.test", "manager-password-123")
        for update in ({"active":False},{"email":"hijack@cerato.test"},{"role":"user"},
                       {"new_password":"attacker-password-123"}):
            with self.assertRaises(Forbidden):
                self.store.manage_account(admin, a["id"], **update)
        with self.assertRaises(Forbidden):
            self.store.manage_account(admin, manager["id"], active=False)
        with self.assertRaises(Forbidden):
            self.store.create_account(admin, "owner2@cerato.test", "owner2-password-123", "owner")

    def test_viewer_is_read_only_and_must_be_redacted(self):
        a, _ = self._actor("main@cerato.test", "owner-secret-password-123")
        self.store.create_account(a, "viewer@cerato.test", "viewer-password-123", "user")
        user, _ = self._actor("viewer@cerato.test", "viewer-password-123")
        self.store.require_permission(user, "view")
        for permission in ("view_sensitive", "network_write", "accounts_manage", "updates_manage"):
            with self.assertRaises(Forbidden):
                self.store.require_permission(user, permission)
        raw = {"peers":{"r530":{"ip":"10.77.0.2","pubkey":"sensitive","endpoint":"1.2.3.4",
                                 "last_handshake":0}}, "pool":["54.37.165.151"],
               "gateway_private_key":"sensitive", "dashboard_mode":"live", "tunnel_active":True}
        result = viewer_projection(raw)
        self.assertEqual(result["machine_count"],1)
        self.assertNotIn("peers",result)
        self.assertNotIn("pool",result)
        self.assertNotIn("gateway_private_key",result)
        self.assertNotIn("ip",result["machines"][0])

    def test_password_change_requires_current_and_revokes_sessions(self):
        a, session = self._actor("main@cerato.test", "owner-secret-password-123")
        with self.assertRaises(InvalidCredentials):
            self.store.change_own_identity(a, "wrong-password", new_password="changed-password-123")
        self.store.change_own_identity(a, "owner-secret-password-123",
                                       email="new-main@cerato.test", new_password="changed-password-123")
        with self.assertRaises(InvalidCredentials):
            self.store.actor(session["session"])
        new_actor, _ = self._actor("new-main@cerato.test", "changed-password-123")
        self.assertEqual(new_actor["id"],a["id"])

    def test_bruteforce_counters_persist(self):
        for i in range(8):
            with self.assertRaises(InvalidCredentials):
                self.store.login("main@cerato.test","not-the-password","203.0.113.77")
        with self.store._db() as db:
            row = db.execute("SELECT count(*) AS n FROM failed_logins WHERE attempts>=8").fetchone()
            self.assertGreaterEqual(row["n"],1)
        with self.assertRaises(InvalidCredentials):
            self.store.login("main@cerato.test","owner-secret-password-123","203.0.113.77")

    def test_cookie_security_attributes(self):
        cookie = secure_cookie("opaque-token")
        for prop in ("HttpOnly","Secure","SameSite=Strict","Max-Age=28800"):
            self.assertIn(prop,cookie)


if __name__ == "__main__":
    unittest.main()

"""Permissions must be enforced on the server, not by hidden UI controls."""
import sys
import time
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security"))

from auth_store import AuthStore, Forbidden
from mfa import code_for_counter
from access_policy import authorize, required_permission


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = AuthStore(Path(self.tmp.name) / "private" / "accounts.db")
        self.store.setup_owner(self.store.issue_bootstrap_token(), "main@cerato.test", "owner-password-example")
        challenge = self.store.login("main@cerato.test", "owner-password-example", "127.0.0.1")
        self.assertTrue(challenge["mfa_required"])
        owner_s = self.store.complete_mfa(challenge["challenge"],
                                         code_for_counter(challenge["otp_secret"], int(time.time()) // 30))
        owner = self.store.actor(owner_s["session"])
        self.store.create_account(owner, "user@cerato.test", "viewer-password-example", "user")
        self.owner_s = owner_s
        self.viewer_s = self.store.login("user@cerato.test", "viewer-password-example", "192.0.2.3")

    def test_unknown_routes_fail_closed(self):
        for route in ("/api/debug/dump", "/api/secret", "/api/updates/private", "/api/accounts/1/owner"):
            with self.assertRaises(Forbidden):
                required_permission("GET", route)

    def test_viewer_reads_status_but_not_sensitive_resources(self):
        s = self.viewer_s
        actor = authorize(self.store, s["session"], "GET", "/api/status")
        self.assertEqual(actor["role"], "user")
        for route in ("/api/events", "/api/wg-config", "/api/nft-preview", "/api/accounts", "/api/updates"):
            with self.assertRaises(Forbidden):
                authorize(self.store, s["session"], "GET", route)

    def test_viewer_cannot_mutate_network_or_accounts_or_updates(self):
        s = self.viewer_s
        for route in ("/api/peers", "/api/enroll/token", "/api/nat/add", "/api/ip/remove",
                      "/api/accounts", "/api/updates/install", "/api/updates/rollback"):
            with self.assertRaises(Forbidden):
                authorize(self.store, s["session"], "POST", route, csrf=s["csrf"])

    def test_admin_permissions_still_require_csrf(self):
        s = self.owner_s
        with self.assertRaises(Forbidden):
            authorize(self.store, s["session"], "POST", "/api/peers", csrf="invalid")
        actor = authorize(self.store, s["session"], "POST", "/api/peers", csrf=s["csrf"])
        self.assertEqual(actor["role"], "owner")


if __name__ == "__main__":
    unittest.main()

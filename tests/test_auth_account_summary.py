"""Native account summaries must never expose sessions, MFA seeds or credentials."""
from pathlib import Path
import tempfile
import time
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import AuthStore, Forbidden
from mfa import code_for_counter

class AccountSummaryTests(unittest.TestCase):
    def test_owner_admin_and_user_safe_mfa_session_badges(self):
        with tempfile.TemporaryDirectory() as d:
            store=AuthStore(Path(d)/"private/accounts.sqlite3")
            store.setup_owner(store.issue_bootstrap_token(),
                              "owner@cerato.test","owner-password-strong-12345")
            challenge=store.login("owner@cerato.test",
                                  "owner-password-strong-12345","127.0.0.1")
            owner_session=store.complete_mfa(
                challenge["challenge"],
                code_for_counter(challenge["otp_secret"],int(time.time())//30))
            owner=store.actor(owner_session["session"])
            admin=store.create_account(owner,"admin@cerato.test",
                                        "admin-password-strong-12345","admin")
            user=store.create_account(owner,"viewer@cerato.test",
                                       "viewer-password-strong-12345","user")
            list_before=store.list_accounts(owner)
            assert len(list_before)==3
            owner_row=next(row for row in list_before if row["role"]=="owner")
            admin_row=next(row for row in list_before if row["role"]=="admin")
            user_row=next(row for row in list_before if row["role"]=="user")
            self.assertTrue(owner_row["mfa_enabled"])
            self.assertEqual(owner_row["active_sessions"],1)
            self.assertFalse(admin_row["mfa_enabled"])
            self.assertEqual(admin_row["active_sessions"],0)
            self.assertEqual(user_row["active_sessions"],0)
            viewer_session=store.login("viewer@cerato.test",
                                       "viewer-password-strong-12345","127.0.0.1")
            viewer=store.actor(viewer_session["session"])
            with self.assertRaises(Forbidden):
                store.list_accounts(viewer)
            after=store.list_accounts(owner)
            self.assertEqual(next(x for x in after if x["id"]==user["id"])
                             ["active_sessions"],1)
            for row in after:
                self.assertEqual(set(row),{"id","email","role","active",
                                           "mfa_enabled","active_sessions"})
                self.assertNotIn("password",str(row).lower())
                self.assertNotIn("secret",str(row).lower())
                self.assertNotIn("tokenhash",str(row).lower())

if __name__=="__main__":
    unittest.main()

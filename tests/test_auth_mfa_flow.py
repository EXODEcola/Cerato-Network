"""Integration tests for mandatory owner/admin MFA; no real gateway touched."""
import sys
import time
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"security"))
from auth_store import AuthStore, InvalidCredentials
from mfa import code_for_counter

class MandatoryMFATests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=AuthStore(Path(self.tmp.name)/"private"/"auth.db")
        self.db.setup_owner(self.db.issue_bootstrap_token(),
                            "owner@example.org", "my-very-long-owner-password")

    def test_password_alone_never_authenticates_owner(self):
        start=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        self.assertTrue(start["mfa_required"])
        self.assertTrue(start["mfa_setup"])
        self.assertNotIn("session",start)
        with self.assertRaises(InvalidCredentials):
            self.db.actor("fake-session-token-with-enough-bytes")
        finish=self.db.complete_mfa(start["challenge"],code_for_counter(start["otp_secret"],int(time.time())//30))
        self.assertEqual(finish["account"]["role"],"owner")
        self.assertEqual(len(finish["recovery_codes"]),8)
        self.assertEqual(self.db.actor(finish["session"])["role"],"owner")
        with self.assertRaises(InvalidCredentials):
            self.db.complete_mfa(start["challenge"],code_for_counter(start["otp_secret"],int(time.time())//30))

    def test_five_failed_otp_attempts_revoke_challenge(self):
        start=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        for _ in range(5):
            with self.assertRaises(InvalidCredentials):
                self.db.complete_mfa(start["challenge"],"invalid-code")
        with self.assertRaises(InvalidCredentials):
            self.db.complete_mfa(start["challenge"],code_for_counter(start["otp_secret"],int(time.time())//30))

    def test_password_cannot_generate_unlimited_otp_challenges(self):
        for _ in range(6):
            step=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
            self.assertTrue(step["mfa_required"])
        with self.assertRaises(InvalidCredentials):
            self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")

    def test_single_use_recovery_and_replay_protection(self):
        first=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        step=int(time.time())//30
        finish=self.db.complete_mfa(first["challenge"],code_for_counter(first["otp_secret"],step))
        self.assertTrue(finish["recovery_codes"])
        next_login=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        self.assertFalse(next_login["mfa_setup"])
        self.assertNotIn("otp_secret",next_login)
        with self.assertRaises(InvalidCredentials):
            self.db.complete_mfa(next_login["challenge"],code_for_counter(first["otp_secret"],step))
        backup=finish["recovery_codes"][0]
        recovered=self.db.complete_mfa(next_login["challenge"],backup)
        self.assertEqual(recovered["account"]["role"],"owner")
        third=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        with self.assertRaises(InvalidCredentials):
            self.db.complete_mfa(third["challenge"],backup)

    def test_reader_keeps_simple_login(self):
        first=self.db.login("owner@example.org","my-very-long-owner-password","127.0.0.1")
        root=self.db.complete_mfa(first["challenge"],code_for_counter(first["otp_secret"],int(time.time())//30))
        account=self.db.create_account(root["account"],"viewer@example.org","read-only-password-123","user")
        self.assertEqual(account["role"],"user")
        login=self.db.login("viewer@example.org","read-only-password-123","127.0.0.1")
        self.assertIn("session",login)
        self.assertNotIn("mfa_required",login)

if __name__=="__main__":
    unittest.main()

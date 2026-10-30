"""AES-GCM key separation and MFA seed confidentiality tests."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import AuthStore, AuthError
from secretbox import SecretBox, SecretBoxError


class MFASecretEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"private"/"accounts.sqlite"
        self.store=AuthStore(self.path)
        self.store.setup_owner(self.store.issue_bootstrap_token(),
                               "owner@example.org","long-owner-password-for-tests")

    def test_secret_not_plaintext_in_db_and_key_is_private(self):
        challenge=self.store.login("owner@example.org","long-owner-password-for-tests","127.0.0.1")
        self.assertTrue(challenge["mfa_setup"])
        secret=challenge["otp_secret"]
        with self.store._db() as db:
            row=db.execute("SELECT secret FROM mfa").fetchone()
            self.assertTrue(row["secret"].startswith("enc:v1:"))
            self.assertNotIn(secret,row["secret"])
        key=self.path.parent/"mfa-encryption.key"
        self.assertTrue(key.is_file())
        self.assertEqual(key.stat().st_mode & 0o777,0o600)
        self.assertEqual(len(key.read_bytes()),32)
        reopened=AuthStore(self.path)
        another=reopened.login("owner@example.org","long-owner-password-for-tests","127.0.0.1")
        self.assertEqual(secret,another["otp_secret"])

    def test_ciphertext_tampering_and_wrong_account_are_rejected(self):
        box=SecretBox(self.path.parent/"mfa-encryption.key")
        payload=box.seal("OTPSECRETEXAMPLE",4)
        self.assertEqual(box.open(payload,4),"OTPSECRETEXAMPLE")
        with self.assertRaises(SecretBoxError):
            box.open(payload,5)
        changed=payload[:-1]+("A" if payload[-1]!="A" else "B")
        with self.assertRaises(SecretBoxError):
            box.open(changed,4)

    def test_missing_key_never_silently_rotates_existing_database(self):
        key=self.path.parent/"mfa-encryption.key"
        key.unlink()
        with self.assertRaises(AuthError):
            AuthStore(self.path)
        self.assertFalse(key.exists())

    def test_reject_insecure_or_symlinked_keys(self):
        key=self.path.parent/"mfa-encryption.key"
        key.chmod(0o644)
        with self.assertRaises(SecretBoxError):
            SecretBox(key)
        key.chmod(0o600)
        key.unlink()
        key.symlink_to(self.path)
        with self.assertRaises(SecretBoxError):
            SecretBox(key)


if __name__=="__main__":
    unittest.main()

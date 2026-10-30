"""Tests RFC6238 / TOTP including replay prevention."""
import base64
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"security"))
from mfa import generate_secret, code_for_counter, verify, enrollment_uri, recovery_codes, consume_recovery

class MFATests(unittest.TestCase):
    def test_rfc6238_vector_and_time_skew(self):
        secret=base64.b32encode(b"12345678901234567890").decode().rstrip("=")
        self.assertEqual(code_for_counter(secret,1,digits=8),"94287082")
        self.assertEqual(code_for_counter(secret,1,digits=6),"287082")
        self.assertEqual(verify(secret,"287082",at=59),1)
        self.assertIsNone(verify(secret,"287082",at=59,last_counter=1))

    def test_new_secrets_and_url(self):
        secret=generate_secret()
        self.assertGreaterEqual(len(secret),30)
        uri=enrollment_uri(secret,"admin@example.org")
        self.assertIn("otpauth://totp/",uri)
        self.assertIn("secret="+secret,uri)
        self.assertIsNone(verify(secret,"not a code",at=100))

    def test_recovery_codes_are_one_time(self):
        raw,stored=recovery_codes()
        self.assertEqual(len(raw),8)
        self.assertNotIn(raw[0],stored)
        ok,left=consume_recovery(raw[0],stored)
        self.assertTrue(ok)
        ok,rest=consume_recovery(raw[0],left)
        self.assertFalse(ok)
        self.assertEqual(left,rest)

if __name__=="__main__":
    unittest.main()

"""Bootstrap pins the operator-approved identity before touching the OVH engine."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from prepare_trusted_github_public import approved_public_key,BootstrapError
from sync_github_signed_release import RELEASES_API

class ApprovedGHBootstrapTests(unittest.TestCase):
    def test_refuses_unknown_fingerprint_and_no_release_before_writes(self):
        with tempfile.TemporaryDirectory() as root:
            out=Path(root)/"pub.pem"
            with self.assertRaises(BootstrapError):
                approved_public_key("not-a-fingerprint",out)
            self.assertFalse(out.exists())
            with patch("prepare_trusted_github_public.discover",return_value=None):
                with self.assertRaises(BootstrapError):
                    approved_public_key("a"*64,out)
            self.assertFalse(out.exists())

    def test_one_time_command_requires_approved_fingerprint(self):
        script=(ROOT/"scripts/connect-github-updates.sh").read_text()
        self.assertIn("prepare_trusted_github_public.py",script)
        self.assertLess(script.index("prepare_trusted_github_public.py"),
                        script.index("finalize-ovh-web-updates.sh"))
        self.assertIn("sync_github_signed_release.py --install",script)
        for forbidden in ("ssh ","scp ","wg set","nft ","iptables ","openssl genpkey",
                          "cerato-updatectl apply","CERATO_BUILD"):
            self.assertNotIn(forbidden,script)
        result=subprocess.run(["bash","-n",str(ROOT/"scripts/connect-github-updates.sh")],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=="__main__":
    unittest.main()

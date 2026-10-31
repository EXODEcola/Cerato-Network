"""Ensure mirror timers never accept arbitrary code or trigger installation."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]


class MirrorTimerContract(unittest.TestCase):
    def test_timer_contains_only_pinned_public_release_mirror(self):
        src=(ROOT/"scripts/enable-github-release-mirror.sh").read_text()
        for required in ("sync_github_signed_release.py --install",
                         "OnUnitInactiveSec=4h",
                         "ReadWritePaths=/srv/cerato-releases/public/cerato-releases",
                         "NoNewPrivileges=true"):
            self.assertIn(required,src)
        for forbidden in ("cerato-updatectl apply","ssh ","scp ","curl -k","wg set","nft ",
                          "systemctl restart cerato-network-web.service","openssl genpkey"):
            self.assertNotIn(forbidden,src)
        result=subprocess.run(["bash","-n",str(ROOT/"scripts/enable-github-release-mirror.sh")],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=="__main__":
    unittest.main()

"""Verify exact distribution URL and scoped same-host Nginx sample."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
from remote import _base, DistributionError

PUBLIC_BASE="https://51.210.223.57/cerato-releases/"
SNIPPET=ROOT/"deploy/releases.same-host-location.conf"
PREPARE=ROOT/"scripts/prepare-same-host-releases.sh"


class SameHostReleaseTests(unittest.TestCase):
    def test_https_ip_base_is_supported_without_rewriting_panel_root(self):
        self.assertEqual(_base(PUBLIC_BASE), PUBLIC_BASE)
        self.assertEqual(_base(PUBLIC_BASE.rstrip("/")),PUBLIC_BASE)
        for path in ("channels/beta.json","channels/beta.sig",
                     "releases/v0.1.0-beta.1/manifest.json",
                     "releases/v0.1.0-beta.1/manifest.sig",
                     "releases/v0.1.0-beta.1/cerato-network-release.zip"):
            self.assertTrue((PUBLIC_BASE+path).startswith(PUBLIC_BASE))
        with self.assertRaises(DistributionError):
            _base("http://51.210.223.57/cerato-releases/")
        with self.assertRaises(DistributionError):
            _base("https://51.210.223.57:8787/cerato-releases/")

    def test_nginx_location_does_not_change_the_main_panel(self):
        source=SNIPPET.read_text(encoding="utf8")
        self.assertIn("location ^~ /cerato-releases/",source)
        self.assertIn("auth_basic off;",source)
        self.assertIn("limit_except GET HEAD",source)
        self.assertIn("root /srv/cerato-releases/public;",source)
        self.assertIn("try_files $uri =404;",source)
        self.assertIn("return 404;",source)
        self.assertNotIn("proxy_pass",source)
        self.assertNotIn("listen 443",source.split("\nlocation ^~",1)[-1])
        self.assertNotIn("private_key",source)
        self.assertNotIn("access_log off",source)

    def test_prepare_script_is_noninvasive(self):
        source=PREPARE.read_text(encoding="utf8")
        for forbidden in ("systemctl restart","wg set","nft ","iptables",
                          "nginx -s reload","/etc/nginx/sites-enabled"):
            self.assertNotIn(forbidden,source)
        self.assertIn("--check",source)
        self.assertIn("--prepare",source)
        result=subprocess.run(["bash","-n",str(PREPARE)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=="__main__":
    unittest.main()

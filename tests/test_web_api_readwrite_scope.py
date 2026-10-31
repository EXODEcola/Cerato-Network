"""Regression: fix read-only systemd updater lock without disabling sandbox."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"scripts/repair-web-update-api-503.sh"

class WebAPIReadWriteScope(unittest.TestCase):
    def test_bash_is_valid(self):
        v=subprocess.run(["bash","-n",str(FILE)],capture_output=True,text=True)
        self.assertEqual(v.returncode,0,v.stderr)

    def test_exact_private_directory_instead_of_sandbox_bypass(self):
        s=FILE.read_text()
        self.assertIn("ReadWritePaths=/var/lib/cerato-network-updates",s)
        self.assertIn("ProtectSystem=strict",s)
        self.assertIn("0700",s)
        self.assertIn('sudo -u "$WEB_USER" sudo -n "$CTL" status',s)
        self.assertIn("systemctl daemon-reload",s)
        self.assertIn('systemctl restart "$UNIT"',s)
        self.assertIn('[[ "$(network_hash)" == "$BEFORE" ]]',s)
        self.assertIn("cerato-network-web.service.d",s)
        for forbidden in ("ProtectSystem=off","ProtectSystem=false","NoNewPrivileges=false",
                          "chmod -R","chmod 777","auth_basic off",
                          "systemctl restart wg-quick","wg set","nft ","iptables ","scp ",
                          "ssh ","cerato-build","nginx -s reload"):
            self.assertNotIn(forbidden,s)

    def test_preserves_existing_configuration(self):
        s=FILE.read_text()
        self.assertIn('Fichier drop-in existant différent : refus de l',s)
        self.assertIn('if [[ "$CREATED" == 1 ]]',s)
        self.assertIn('rm -f -- "$DROPIN"',s)
        self.assertIn("Aucune modification de fichiers ou services.",s)


if __name__=="__main__":
    unittest.main()

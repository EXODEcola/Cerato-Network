"""OVH one-command activation must not assume the release signer exists."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]


class FinalOVHCommandTests(unittest.TestCase):
    def test_script_is_bash_valid(self):
        file=ROOT/"scripts/finalize-ovh-web-updates.sh"
        result=subprocess.run(["bash","-n",str(file)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_blocks_unapproved_signer_before_replacing_engine(self):
        script=(ROOT/"scripts/finalize-ovh-web-updates.sh").read_text()
        self.assertIn('if [[ ! -f "$TRUST" && ${#ARGS[@]} == 0 ]]',script)
        self.assertLess(script.index('if [[ ! -f "$TRUST" && ${#ARGS[@]} == 0 ]]'),
                        script.index('install -o root -g root -m 0755 "$ROOT/updates/live_controller.py"'))
        self.assertIn("exit 3",script)
        self.assertIn("Clé déjà épinglée : remplacement interdit",script)

    def test_preserves_network_and_build(self):
        script=(ROOT/"scripts/finalize-ovh-web-updates.sh").read_text()
        self.assertIn('BEFORE="$(net_hash)"',script)
        self.assertIn('AFTER="$(net_hash)"',script)
        self.assertIn("cp -p \"$BACKUP/$rel\" \"$ENGINE/$rel\" || true",script)
        for forbidden in ("ssh ","scp ","wg set","nft ","iptables ","cerato-build",
                          "git clone", "openssl genpkey", "auth_basic off"):
            self.assertNotIn(forbidden,script)
        self.assertIn('python3 "$ROOT/integrations/activate_live_updates.py" --install',script)

    def test_browser_controls_install(self):
        script=(ROOT/"scripts/enable-live-update-check.timer.sh").read_text()
        self.assertIn("ExecStart=/usr/local/sbin/cerato-updatectl check",script)
        self.assertNotIn("ExecStart=/usr/local/sbin/cerato-updatectl apply",script)


if __name__=="__main__":
    unittest.main()

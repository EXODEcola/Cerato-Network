"""Regression: signed release permission repair is narrow and fail-closed."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import repair_published_signed_permissions as repair
VERSION="v0.1.0-beta.1"


class PermissionRepairTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        store=self.root/".channel-generations"
        self.generation=store/"generation-1"
        self.generation.mkdir(parents=True)
        self.channel=self.root/"channels"
        self.channel.symlink_to(".channel-generations/generation-1")
        self.release=self.root/"releases"/VERSION
        self.release.mkdir(parents=True)
        for name,value in (
            ("beta.json",json.dumps({"version":VERSION}).encode()),
            ("beta.sig",b"signature")
        ):
            (self.generation/name).write_bytes(value)
        for name in ("manifest.json","manifest.sig","cerato-network-release.zip"):
            (self.release/name).write_bytes(b"validated-in-patched-test")
        for path in (store,self.generation,self.release):
            path.chmod(0o700)
        for path in list(self.generation.iterdir())+list(self.release.iterdir()):
            path.chmod(0o600)

    def _validated(self):
        return patch.multiple(repair,
            _trusted=lambda config:("beta",self.root/"approved.pub"),
            _root=lambda root:None,
            _existing_channels=lambda root:(self.channel,{}),
            _require_owned=lambda path,*,directory:None,
            validate=lambda released,channel,key,kind:(VERSION,{"valid":b"yes"}))

    def test_modes_public_only_after_validation(self):
        with self._validated(),patch.object(repair.os,"geteuid",return_value=0):
            preview=repair.repair(root=self.root,install=False)
            self.assertTrue(preview["signature_verified"])
            self.assertEqual(self.generation.stat().st_mode & 0o777,0o700)
            result=repair.repair(root=self.root,install=True)
            self.assertTrue(result["modes_applied"])
        for folder in (self.root/".channel-generations",self.generation,self.release):
            self.assertEqual(folder.stat().st_mode & 0o777,0o755)
        for file in list(self.generation.iterdir())+list(self.release.iterdir()):
            self.assertEqual(file.stat().st_mode & 0o777,0o644)

    def test_failed_crypto_check_never_changes_modes(self):
        with self._validated(),patch.object(repair,"validate",
                side_effect=repair.PermissionRepairError("invalid signature")):
            with self.assertRaisesRegex(repair.PermissionRepairError,"signature"):
                repair.repair(root=self.root,install=True)
        self.assertEqual(self.generation.stat().st_mode & 0o777,0o700)
        self.assertEqual((self.release/"manifest.json").stat().st_mode & 0o777,0o600)

    def test_rejects_symlink_for_artifact(self):
        payload=self.release/"manifest.json"
        payload.unlink()
        payload.symlink_to(self.root/"outside")
        with self.assertRaises(repair.PermissionRepairError):
            repair._require_owned(payload,directory=False)

    def test_repair_script_only_touches_publisher_and_signed_assets(self):
        script=(ROOT/"scripts/repair-signed-public-downloads.sh").read_text()
        self.assertIn("repair_published_signed_permissions.py",script)
        self.assertIn("cerato-updatectl check",script)
        self.assertNotIn("chmod -R",script)
        for forbidden in ("wg set","iptables ","nft ","systemctl restart",
                          "nginx -s","curl -k","scp ","ssh "):
            self.assertNotIn(forbidden,script)
        run=subprocess.run(["bash","-n",str(ROOT/"scripts/repair-signed-public-downloads.sh")],
                           capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)


if __name__=="__main__":
    unittest.main()

"""Pure, no-execution verification tests for an exact-hash Cerato controller stage."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import verify_staged_routed_controller as validator
import stage_live_routed_controller as staging

SYNTHETIC="""from __future__ import annotations
def render_nft(data):
    entries = [data["existing_nft"]]
    return "".join(entries)
def rewrite_wg_peers(data):
    original = data["existing_wg"]
    temp = data["temporary_sink"]
    temp.write_text(original)
"""


class StageVerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix="cerato-verification-",dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.root.chmod(0o700)
        self.original=self.root/"ceratoctl-original"
        self.original.write_text(SYNTHETIC,encoding="utf8")
        self.original.chmod(0o600)
        self.original_sha=hashlib.sha256(self.original.read_bytes()).hexdigest()
        self.stage=self.root/"patched"
        self.stage.mkdir(mode=0o700)
        self.patch=staging.transform(self.original.read_bytes())
        (self.stage/"ceratoctl").write_bytes(self.patch)
        self.support=self.root/"support"
        self.support.mkdir()
        for dst,src in validator.ORIGIN.items():
            content=(ROOT/"network"/src).read_bytes()
            (self.support/src).write_bytes(content)
            (self.stage/dst).write_bytes(content)
        for item in self.stage.iterdir():
            item.chmod(0o600)

    def verify(self,**kwargs):
        with patch.object(validator,"SOURCE",self.original),patch.object(
                validator,"SOURCE_SHA",self.original_sha):
            return validator.inspect_staged(
                self.stage,original=self.original,support_dir=self.support,
                expected_patched_sha=hashlib.sha256(self.patch).hexdigest(),
                trusted_uid=os.getuid(),**kwargs)

    def test_hashes_and_ast_hooks_without_importing_or_running_controller(self):
        report=self.verify()
        self.assertEqual(report["status"],"review-only-verified")
        self.assertEqual(report["hook_calls"],{"render_nft":1,"rewrite_wg_peers":1})
        self.assertTrue(report["source_unmodified"])
        self.assertFalse(report["network_modified"])
        self.assertFalse(report["ready_to_install"])
        self.assertFalse(report["ready_for_routed_ip"])
        self.assertNotIn("existing_nft",json.dumps(report))
        self.assertEqual(self.original.read_text(),SYNTHETIC)

    def test_tampered_staged_controller_rejected(self):
        (self.stage/"ceratoctl").write_bytes(self.patch+b"\n# altered")
        with self.assertRaisesRegex(validator.VerificationError,"Empreinte"):
            self.verify()

    def test_tampered_support_module_rejected(self):
        helper=self.stage/"routed_firewall.py"
        helper.write_bytes(helper.read_bytes()+b"\n# tampered")
        with self.assertRaisesRegex(validator.VerificationError,"différent"):
            self.verify()

    def test_unexpected_file_in_staging_rejected(self):
        (self.stage/"private-token").write_text("not allowed")
        with self.assertRaisesRegex(validator.VerificationError,"inattendus"):
            self.verify()

    def test_open_permissions_rejected(self):
        self.stage.chmod(0o755)
        with self.assertRaisesRegex(validator.VerificationError,"non privé"):
            self.verify()

    def test_original_changed_rejected(self):
        self.original.write_text(SYNTHETIC+"\n# changed")
        with self.assertRaisesRegex(validator.VerificationError,"changé"):
            self.verify()


if __name__=="__main__":
    unittest.main()

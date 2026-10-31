"""Read-only live engine structure scanner tests: no literal source export."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import inspect_live_network_engine as scanner


class EngineScannerTests(unittest.TestCase):
    def test_structural_inventory_never_includes_secrets_or_source_text(self):
        with tempfile.TemporaryDirectory() as td:
            script=Path(td)/"ceratoctl"
            script.write_text(
                "SECRET = 'DO-NOT-EXPORT-THIS-SAMPLE-PRIVATE-KEY'\n"
                "def render_nft_rules(): return SECRET\n"
                "def save_network_config(): pass\n"
                "def unrelated(): pass\n"
                "class CeratoManager: pass\n",encoding="utf-8")
            with patch.object(scanner,"ALLOWED_ROOTS",(td+"/",)):
                report=scanner.inspect(script)
            self.assertTrue(report["python"])
            self.assertIn("render_nft_rules",report["functions"])
            self.assertIn("save_network_config",report["functions"])
            self.assertNotIn("unrelated",report["functions"])
            self.assertIn("CeratoManager",report["classes"])
            self.assertNotIn("DO-NOT-EXPORT",str(report))
            self.assertEqual(len(report["sha256"]),64)

    def test_non_python_script_never_exposes_lines(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ceratoctl"
            path.write_text("#!/bin/bash\nsecret-password-here\n")
            with patch.object(scanner,"ALLOWED_ROOTS",(td+"/",)):
                report=scanner.inspect(path)
            self.assertFalse(report["python"])
            self.assertNotIn("secret-password-here",str(report))

    def test_reject_symlink_or_untrusted_path(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/"src"
            source.write_text("def render_nat(): pass")
            target=Path(td)/"ceratoctl"
            target.symlink_to(source)
            with patch.object(scanner,"ALLOWED_ROOTS",(td+"/",)):
                report=scanner.inspect(target)
            self.assertFalse(report["exists"])
            self.assertIsNone(report["sha256"])
            self.assertEqual(scanner.inspect("/tmp/unapproved-controller")["exists"],False)


if __name__=="__main__":
    unittest.main()

"""Live UI deployment audit only reports safe structural facts."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

PATH=Path(__file__).resolve().parents[1]/"scripts"/"audit_live_ui_deployment.py"
spec=importlib.util.spec_from_file_location("audit_live_ui_deployment",PATH)
audit_mod=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=audit_mod
spec.loader.exec_module(audit_mod)

class PanelAuditTests(unittest.TestCase):
    def test_legacy_source_report_is_safe_and_exposes_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"web").mkdir()
            (root/"backend").mkdir()
            (root/"backend/server.py").write_text(
                "TOKEN='hidden-secret'\n"
                "def additional_ipctl(*a): pass\n"
                "def netstate(): return {}\n"
                "class H:\n"
                " def do_GET(self):\n"
                "        if p=='/api/status': return self.send_json(200,netstate())\n"
                " def do_POST(self):\n"
                "            if p=='/api/nat/add':\n"
                "                pass\n"
                " # /api/updates is installed\n"
            )
            (root/"web/app.js").write_text(
                "function render(){if(!live)return;\n"
                "function updates(){return 0}\n"
                "const password='not-for-logs';\n"
                "const banner='Une règle NAT redirige un port vers WireGuard';\n"
            )
            (root/"web/style.css").write_text("body{color:#000}\n")
            state=root/"state.json"
            state.write_text(json.dumps({"installed_version":"v0.1.0-beta.1",
                                         "available_version":None,"reason_code":"already_current",
                                         "credentials":"do-not-leak"}))
            report=audit_mod.audit(root,state)
            self.assertTrue(report["candidate_for_safe_staging"])
            self.assertFalse(report["safe_to_apply_automatically"])
            self.assertEqual(report["update"]["installed_version"],"v0.1.0-beta.1")
            self.assertTrue(report["checks"]["legacy_nat_banner_present"])
            self.assertFalse(report["checks"]["routed_allocations_api_installed"])
            self.assertEqual(set(report["hashes"]),{"frontend","backend","style"})
            self.assertNotIn("hidden-secret",json.dumps(report))
            self.assertNotIn("not-for-logs",json.dumps(report))
            self.assertNotIn("do-not-leak",json.dumps(report))

    def test_unknown_source_cannot_be_approved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"web").mkdir()
            (root/"backend").mkdir()
            (root/"backend/server.py").write_text("def fake():return 1\n")
            (root/"web/app.js").write_text("console.log('partial');\n")
            (root/"web/style.css").write_text("body{color:black}\n")
            report=audit_mod.audit(root,root/"absent.json")
            self.assertFalse(report["candidate_for_safe_staging"])
            self.assertFalse(report["checks"]["legacy_graphite_frontend"])
            self.assertEqual(report["update"],{})

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"web").mkdir()
            (root/"backend").mkdir()
            (root/"backend/server.py").write_text("data\n")
            (root/"web/app.js").symlink_to(root/"backend/server.py")
            (root/"web/style.css").write_text("css\n")
            with self.assertRaisesRegex(ValueError,"symbolique"):
                audit_mod.audit(root,root/"absent.json")

if __name__=="__main__":
    unittest.main()

"""No-secrets, no-mutation inventory tests for RISE-1 auth migration."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from inspect_live_auth_compat import inspect, InventoryError


class LiveAuthCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.workspace=tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.base=Path(self.workspace.name)
        self.backend=self.base/"server.py"
        self.frontend=self.base/"app.js"
        self.backend.write_text('''
SECRET_PASSWORD = "never-output-this-value"
API_KEY = "very-private-test-key"
def netstate(): return {}
def audit(*args): pass
class Gateway:
    def do_GET(self):
        p="/api/status"
        q="/api/updates"
    def do_POST(self):
        p="/api/nat/add"
        q="/api/accounts"
    def check_session(self,write=False): pass
    def read_body(self): return {}
    def send_json(self,*args): pass
''',encoding="utf8")
        self.frontend.write_text('''const authSecret="must-not-appear";
const navigation=[["overview","Vue d'ensemble"],["machines","Machines"],["updates","Mises à jour"]];''',encoding="utf8")

    def test_report_lists_only_allowlisted_structure(self):
        report=inspect(self.backend,self.frontend)
        self.assertEqual(report["format"],"cerato-live-auth-compat-v1")
        self.assertTrue(report["compatible_for_adapter_design"])
        self.assertEqual(report["api_routes"],[
            "/api/accounts","/api/nat/add","/api/status","/api/updates"
        ])
        self.assertIn("updates",report["ui_sections"])
        self.assertIn("check_session",report["auth_hooks"])
        self.assertEqual(report["server_sha256"],hashlib.sha256(self.backend.read_bytes()).hexdigest())
        self.assertNotIn("SECRET_PASSWORD",json.dumps(report))
        self.assertNotIn("never-output-this-value",json.dumps(report))
        self.assertNotIn("API_KEY",json.dumps(report))
        self.assertNotIn("authSecret",json.dumps(report))
        self.assertNotIn("very-private-test-key",json.dumps(report))
        self.assertFalse(report["direct_network_mutations"])

    def test_unknown_route_strings_and_address_values_not_exported(self):
        self.backend.write_text(self.backend.read_text()+
            '\nSOME_ENDPOINT="/private/very-secret"\nIP_ADDR="54.37.165.151"\n',encoding="utf8")
        report=inspect(self.backend,self.frontend)
        packed=json.dumps(report)
        self.assertNotIn("54.37.165.151",packed)
        self.assertNotIn("very-secret",packed)
        self.assertNotIn("/private/",packed)

    def test_symlink_rejected(self):
        link=self.base/"link.py"
        link.symlink_to(self.backend)
        with self.assertRaises(InventoryError):
            inspect(link,self.frontend)

    def test_readonly_no_changes(self):
        server_before=self.backend.read_bytes()
        client_before=self.frontend.read_bytes()
        inspect(self.backend,self.frontend)
        self.assertEqual(self.backend.read_bytes(),server_before)
        self.assertEqual(self.frontend.read_bytes(),client_before)


if __name__=="__main__":
    unittest.main()

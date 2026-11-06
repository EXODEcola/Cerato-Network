"""Realistic synthetic POST NAT dispatcher probe regression tests."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"probe_live_nat_dispatch.py"
spec=importlib.util.spec_from_file_location("probe_nat",SCRIPT)
probe=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=probe
spec.loader.exec_module(probe)

class ProbeNATDispatchTests(unittest.TestCase):
    def test_detects_double_quotes_and_body_read_without_source_export(self):
        source='''SECRET_PASSWORD = "unique-password-not-for-output"
class Handler:
    def do_POST(self):
        p=self.path
        if not self.check_session(write=True):return
        b=self.read_body()
        if p == "/api/nat/add":
            token="never-print-me"
            self.ctl("nat-add",b)
        elif p == '/api/nat/remove':
            self.ctl("nat-remove",b)
'''
        found=probe.analyze(source)
        self.assertTrue(found["nat_add_direct_branch_found"])
        self.assertEqual(len(found["handlers"]),1)
        branches=found["handlers"][0]["nat_branches"]
        self.assertEqual([x["routes"] for x in branches],
                         [["/api/nat/add"],["/api/nat/remove"]])
        self.assertTrue(branches[0]["before_branch_write_auth_present"])
        self.assertEqual(branches[0]["before_branch_body_read"],"b")
        packed=json.dumps(found)
        self.assertNotIn("unique-password-not-for-output",packed)
        self.assertNotIn("never-print-me",packed)
        self.assertNotIn("nat-add\",b",packed)
        self.assertFalse(found["network_modified"])

    def test_membership_branch_is_detected_but_not_directly_approvable(self):
        source="""class H:
    def do_POST(self):
        p=self.path
        if p in ('/api/nat/add','/api/nat/remove'):
            return 1
"""
        report=probe.analyze(source)
        self.assertFalse(report["nat_add_direct_branch_found"])
        self.assertEqual(report["handlers"][0]["nat_branches"][0]["syntax"],
                         "noncanonical-expression")

    def test_non_nat_routes_are_not_exposed(self):
        source="""class H:
    def do_POST(self):
        if p == '/api/password-reset-token':
            return SECRET
"""
        result=probe.analyze(source)
        self.assertEqual(result["handlers"][0]["nat_branches"],[])
        self.assertNotIn("password-reset-token",json.dumps(result))

    def test_readonly_file_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend=Path(tmp)/"server.py"
            backend.write_text('class Handler:\n'
                               '    def do_POST(self):\n'
                               '        if p == "/api/nat/add":pass\n')
            before=backend.read_bytes()
            result=probe.audit(backend)
            self.assertTrue(result["nat_add_direct_branch_found"])
            self.assertEqual(backend.read_bytes(),before)

    def test_unknown_path_and_bad_source_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"missing.py"
            with self.assertRaises(probe.ProbeError):
                probe.audit(p)
            q=Path(tmp)/"linked.py"
            q.symlink_to(p)
            with self.assertRaises(probe.ProbeError):
                probe.audit(q)
        with self.assertRaises(SyntaxError):
            probe.analyze("class x :\n def : broken")

if __name__=="__main__":
    unittest.main()

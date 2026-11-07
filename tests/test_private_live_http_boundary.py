"""Legacy private backend AST audit must never execute or export sources."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import audit_private_live_http_boundary as probe

CONFIDENTIAL="VERY_PRIVATE_SERVER_TOKEN_DO_NOT_PRINT"
PY=f'''SECRET="{CONFIDENTIAL}"
def netstate(): return {{"ok": True}}
class Handler:
    def check_session(self,write=False): return True
    def send_json(self,code,payload): return None
    def do_GET(self):
        if self.path=="/api/status": return self.send_json(200,{{}})
        if self.path=="/api/ip/allocations": return self.send_json(200,{{}})
    def do_POST(self):
        if self.path=="/api/nat/add":
            return self.send_json(200,{{}})
if __name__=="__main__":
    fake_server()
'''
POLICY=(ROOT/"security/legacy_policy.py").read_bytes()


class PrivateBoundaryTests(unittest.TestCase):
    def test_known_source_never_reveals_private_literals(self):
        result=probe.risk_map(PY.encode(),POLICY)
        self.assertEqual(result["handler_count"],1)
        self.assertEqual(result["unwrapped_http_method_count"],0)
        self.assertEqual(result["unrecognized_api_route_count"],0)
        self.assertGreater(result["rbac_policy_pair_count"],10)
        self.assertTrue(result["legacy_http_isolation_mandatory"])
        self.assertFalse(result["full_backend_execution_review_complete"])
        self.assertFalse(result["http_socket_test_with_actual_backend_complete"])
        self.assertNotIn(CONFIDENTIAL,json.dumps(result))
        self.assertNotIn("fake_server",json.dumps(result))

    def test_unknown_api_route_count_only(self):
        input_src=PY.replace("fake_server()",'''fake_server()
UNKNOWN="/api/undocumented-network-mutation"''')
        result=probe.risk_map(input_src.encode(),POLICY)
        self.assertEqual(result["unrecognized_api_route_count"],1)
        self.assertNotIn("undocumented",json.dumps(result))

    def test_additional_http_method_is_flagged(self):
        new=PY.replace("    def do_GET(self):",
                       "    def do_PUT(self): return None\n    def do_GET(self):")
        result=probe.risk_map(new.encode(),POLICY)
        self.assertEqual(result["unwrapped_http_method_count"],1)

    def test_ambiguous_http_handlers_refused(self):
        new=PY+"\n"+PY[PY.index("class Handler:"):PY.index("if __name__")].replace(
                "class Handler:","class SecondHandler:")
        with self.assertRaises(probe.ExecutionBoundaryError):
            probe.risk_map(new.encode(),POLICY)

    def test_policy_is_literal_and_nonoverlapping(self):
        pairs=probe.parsed_policy(POLICY)
        self.assertIn(("GET","/api/status"),pairs)
        self.assertIn(("POST","/api/nat/add"),pairs)
        with self.assertRaises(probe.ExecutionBoundaryError):
            probe.parsed_policy(POLICY.replace(
                b'("GET","/api/status")',
                b'("GET","/api/status"),("GET","/api/status")'))
        with self.assertRaises(probe.ExecutionBoundaryError):
            probe.parsed_policy(b"PUBLIC=set(unknown_runtime_source)")

    def test_runtime_and_candidate_are_checked_without_execution(self):
        from types import SimpleNamespace
        with patch.object(probe.os,"geteuid",return_value=0), \
             patch.object(probe,"safe_read",side_effect=[
                 PY.encode(),POLICY]), \
             patch.object(probe,"digest",return_value=probe.EXPECTED["server_sha256"]), \
             patch.object(probe,"candidate_verified",return_value=True), \
             patch.object(probe,"check_runtime",return_value={
                 "argon2id_checked":True,"aes_gcm_checked":True}):
            result=probe.inspect()
        self.assertFalse(result["safe_to_execute_private_backend"])
        self.assertFalse(result["safe_to_cut_over"])
        self.assertTrue(result["inactive_candidate_integrity_verified"])
        for key in ("production_modified","network_modified",
                    "nginx_modified","service_restarted",
                    "private_source_exported","production_account_created"):
            self.assertFalse(result[key])
        self.assertNotIn(CONFIDENTIAL,json.dumps(result))

if __name__=="__main__":
    unittest.main()

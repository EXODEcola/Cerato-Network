"""Private historical startup classification must not execute or export source."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"integrations"))
import audit_private_live_startup_map as checker

SECRET="ULTRA_CONFIDENTIAL_WG_SEED_IGNORE"
SOURCE=f'''"""Confidential backend code never executed here."""
import os
import subprocess
from pathlib import Path
SECRET="{SECRET}"
RUNTIME=socket.bind(("127.0.0.1",8787))
CONFIG={{"a":1}}
@decorator
def first(x=factory.connect()):
    return subprocess.run(["not-executed"])
class Historical:
    v=service.connect("private")
    def do_GET(self):
        return api.run("test")
if __name__=="__main__":
    server.serve_forever()
if True:
    marker=other.run("on-import")
'''

class StartupClassification(unittest.TestCase):
    def test_classifies_import_guard_deferred_without_execution(self):
        info=checker.startup_profile(SOURCE.encode())
        self.assertEqual(info["format"],"cerato-private-live-startup-map-v1")
        self.assertEqual(info["top_level_imports"],3)
        self.assertEqual(info["top_level_main_guards"],1)
        self.assertEqual(info["top_level_dynamic_assignments"],1)
        self.assertEqual(info["top_level_reference_assignments"],2)
        self.assertEqual(info["top_level_other_runtime_statements"],1)
        self.assertEqual(info["class_bodies_evaluated_on_load"],1)
        self.assertEqual(info["functions_with_decorators"],1)
        self.assertEqual(info["functions_with_defaults"],1)
        self.assertEqual(info["suspected_external_call_sites_at_import"],4)
        self.assertEqual(info["suspected_external_call_sites_guarded_main"],1)
        self.assertEqual(info["suspected_external_call_sites_deferred"],2)
        self.assertEqual(info["suspected_external_call_sites"],7)
        self.assertFalse(info["static_analysis_can_prove_safe_execution"])
        self.assertFalse(info["safe_to_execute_private_backend"])
        self.assertFalse(info["safe_to_cut_over"])
        self.assertFalse(info["network_modified"])
        self.assertFalse(info["private_source_exported"])
        self.assertNotIn(SECRET,json.dumps(info))
        self.assertNotIn("127.0.0.1",json.dumps(info))
        self.assertNotIn("not-executed",json.dumps(info))

    def test_unsafe_import_cannot_run_during_static_classification(self):
        code=b"""raise RuntimeError('STATIC AUDITOR MUST NOT RUN THIS')
import sys
"""
        report=checker.startup_profile(code)
        self.assertEqual(report["top_level_other_runtime_statements"],1)
        self.assertEqual(report["suspected_external_call_sites"],0)

    def test_main_guard_only_for_exact_name_equality(self):
        source=b"""if __name__ == '__main__':
    danger.bind()
if some_flag:
    danger.connect()
if __name__ != '__main__':
    danger.run()
"""
        info=checker.startup_profile(source)
        self.assertEqual(info["top_level_main_guards"],1)
        self.assertEqual(info["suspected_external_call_sites_guarded_main"],1)
        self.assertEqual(info["suspected_external_call_sites_at_import"],2)

    def test_ast_limit_and_malformed_source_fail_closed(self):
        with self.assertRaises(checker.ExecutionBoundaryError):
            checker.startup_profile(b"def broken(:\n")
        with self.assertRaises(checker.ExecutionBoundaryError):
            checker.startup_profile(b"\xff")

    def test_staged_candidate_auth_decorator_is_an_import_side_effect(self):
        staged=b'''def _cerato_secure_handler(cls):
    store = _CeratoAuthStore("/PRIVATE/DO_NOT_EXPOSE/mfa.db")
    return cls
@_cerato_secure_handler
class Handler:
    pass
'''
        details=checker.staged_candidate_import_profile(staged)
        self.assertTrue(details["candidate_auth_handler_decorated_at_import"])
        self.assertTrue(details["candidate_account_store_constructed_during_import"])
        self.assertTrue(details["candidate_test_must_mask_actual_auth_storage"])
        self.assertNotIn("mfa.db",json.dumps(details))
        self.assertNotIn("PRIVATE",json.dumps(details))
        with self.assertRaises(checker.ExecutionBoundaryError):
            checker.staged_candidate_import_profile(staged.replace(
                b"_CeratoAuthStore",b"OTHER"))
        with self.assertRaises(checker.ExecutionBoundaryError):
            checker.staged_candidate_import_profile(staged.replace(
                b"@_cerato_secure_handler",b""))


    def test_own_preflight_must_recheck_active_private_hash(self):
        payload={"inactive_candidate_integrity_verified":True,
                 "cryptographic_runtime_validated_under_web_user":True,
                 "possible_external_or_socket_call_count":0}
        with patch.object(checker.os,"geteuid",return_value=0), \
             patch.object(checker,"boundary_inspect",return_value=payload), \
             patch.object(checker,"safe_read",return_value=b"x=1"), \
             patch.object(checker,"digest",return_value="0"*64), \
             self.assertRaises(checker.ExecutionBoundaryError):
            checker.inspect()

if __name__=="__main__":
    unittest.main()

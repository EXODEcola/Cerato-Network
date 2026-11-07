"""Private root-runner smoke: test-only account database, no live writes or secrets."""
from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import run_private_native_auth_http_contract as runner

COMPLETE={
    "format":"cerato-native-auth-sandbox-v1",
    "owner_enrolled_with_mfa":True,
    "admin_enrolled_with_mfa":True,
    "user_read_only_and_redacted":True,
    "owner_account_protected":True,
    "csrf_and_origin_enforced":True,
    "historical_login_rejected":True,
    "http_handlers_in_memory":True,
    "test_database_temporary":True,
    "production_network_used":False,
    "production_accounts_used":False,
    "safe_to_cut_over":False,
    "test_requests_checked":26,
}

class PrivateRunnerTests(unittest.TestCase):
    def _setup(self,exit_code=0,output=None):
        stage=Path("/var/tmp/cerato-auth-contract.mocked")
        fakeuser=SimpleNamespace(pw_uid=999,pw_gid=999)
        ctx=[
            patch.object(runner.os,"geteuid",return_value=0),
            patch.object(runner,"check_test_source"),
            patch.object(runner,"check_runtime",return_value={
                "argon2id_checked":True,"aes_gcm_checked":True}),
            patch.object(runner,"verified_candidate",
                         return_value=Path("/var/backups/cerato-private-auth-candidate.mocked")),
            patch.object(runner.pwd,"getpwnam",return_value=fakeuser),
            patch.object(runner.tempfile,"mkdtemp",return_value=str(stage)),
            patch.object(runner,"stage_sandbox",return_value=(
                 stage/"runner.py",stage/"security",stage/"test-only-db")),
            patch.object(runner.subprocess,"run",return_value=SimpleNamespace(
                returncode=exit_code,
                stdout=json.dumps(COMPLETE if output is None else output),
                stderr="ANY HISTORICAL PRIVATE BACKEND DATA")),
            patch.object(runner.shutil,"rmtree"),
        ]
        return ctx

    def test_no_production_operation_and_disposable_data(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks=[stack.enter_context(x) for x in self._setup()]
            result=runner.run()
            self.assertEqual(result["status"],"private_auth_contract_passed")
            self.assertFalse(result["production_accounts_modified"])
            self.assertFalse(result["production_modified"])
            self.assertFalse(result["network_modified"])
            self.assertFalse(result["safe_to_cut_over"])
            self.assertTrue(result["owner_mfa_checked"])
            self.assertTrue(result["admin_mfa_checked"])
            self.assertTrue(result["viewer_rbac_checked"])
            self.assertTrue(result["csrf_origin_checked"])
            self.assertEqual(mocks[7].call_count,1)
            command=mocks[7].call_args.args[0]
            self.assertEqual(command[0],runner.RUNUSER)
            self.assertEqual(command[1:4],["-u","ceratonet","--"])
            self.assertEqual(command[5],"-I")
            self.assertEqual(mocks[8].call_count,1)

    def test_nonzero_child_fails_closed_and_disposes_temp_dir(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks=[stack.enter_context(x) for x in self._setup(exit_code=1)]
            with self.assertRaises(runner.SandboxError) as cm:
                runner.run()
            self.assertNotIn("PRIVATE BACKEND",str(cm.exception))
            self.assertEqual(mocks[8].call_count,1)

    def test_incomplete_contract_must_never_claim_pass(self):
        from contextlib import ExitStack
        bad={**COMPLETE,"admin_enrolled_with_mfa":False}
        with ExitStack() as stack:
            mocks=[stack.enter_context(x) for x in self._setup(output=bad)]
            with self.assertRaises(runner.SandboxError):
                runner.run()
            self.assertEqual(mocks[8].call_count,1)

    def test_error_metadata_is_strictly_sanitized(self):
        private = "PRIVATE_PASSWORD_AND_MFA_SEED_DO_NOT_PRINT"
        stderr = (
            "Traceback: " + private + "\n"
            "CERATO_TEST_STAGE=temporary-database\n"
            "CERATO_TEST_ERROR=PermissionError\n"
        )
        self.assertEqual(
            runner.error_phase("",stderr),
            ("temporary-database","PermissionError","unknown"),
        )
        self.assertEqual(
            runner.error_phase("", "CERATO_TEST_STAGE="+private+"\n"+
                 "CERATO_TEST_ERROR=ConnectionError\n"),
            ("unknown","unknown","unknown"),
        )

    def test_allowed_missing_module_is_reported_without_arbitrary_paths(self):
        stderr=(
            "private.password=SECRET_NOT_FOR_OPERATOR\n"
            "CERATO_TEST_STAGE=module-import\n"
            "CERATO_TEST_ERROR=ModuleNotFoundError\n"
            "CERATO_TEST_MODULE=auth_store\n"
        )
        self.assertEqual(runner.error_phase("",stderr),
                         ("module-import","ModuleNotFoundError","auth_store"))
        self.assertEqual(runner.error_phase(
            "","CERATO_TEST_STAGE=module-import\n"
            "CERATO_TEST_ERROR=ModuleNotFoundError\n"
            "CERATO_TEST_MODULE=private_unknown_host_path\n"),
            ("module-import","ModuleNotFoundError","unknown"))
        self.assertEqual(runner.error_phase(
            "","CERATO_TEST_MODULE=../../etc/shadow\n"),
            ("unknown","unknown","unknown"))

    def test_child_failure_returns_only_phase_and_type(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks=[stack.enter_context(x) for x in self._setup(exit_code=1)]
            mocks[7].return_value.stderr=(
                "private-secret-never-echo\n"
                "CERATO_TEST_STAGE=owner-mfa\n"
                "CERATO_TEST_ERROR=AssertionError\n"
            )
            with self.assertRaises(runner.SandboxError) as cm:
                runner.run()
            message=str(cm.exception)
            self.assertIn("étape=owner-mfa",message)
            self.assertIn("type=AssertionError",message)
            self.assertNotIn("private-secret-never-echo",message)
            self.assertEqual(mocks[8].call_count,1)

    def test_child_missing_dependency_is_the_only_extra_output(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks=[stack.enter_context(x) for x in self._setup(exit_code=1)]
            mocks[7].return_value.stderr=(
                "SECRET_HOST_PRIVATE_TRACEBACK\n"
                "CERATO_TEST_STAGE=module-import\n"
                "CERATO_TEST_ERROR=ModuleNotFoundError\n"
                "CERATO_TEST_MODULE=cryptography\n"
            )
            with self.assertRaises(runner.SandboxError) as cm:
                runner.run()
            msg=str(cm.exception)
            self.assertIn("module_manquant=cryptography",msg)
            self.assertNotIn("SECRET_HOST_PRIVATE_TRACEBACK",msg)
            self.assertEqual(mocks[8].call_count,1)

    def test_unusable_crypto_fails_before_privileged_work(self):
        with patch.object(runner.os,"geteuid",return_value=0), \
             patch.object(runner,"check_test_source"), \
             patch.object(runner,"check_runtime",return_value={"argon2id_checked":False}), \
             patch.object(runner,"verified_candidate") as candidate:
            with self.assertRaises(runner.SandboxError):
                runner.run()
            candidate.assert_not_called()

if __name__=="__main__":
    unittest.main()

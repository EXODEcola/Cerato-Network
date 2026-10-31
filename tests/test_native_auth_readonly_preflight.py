"""Native login readiness inventory: read-only, bounded, zero raw secrets."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import preflight_native_auth as preflight


class NativeAuthReadOnlyPreflightTests(unittest.TestCase):
    def test_safe_report_is_redacted_and_never_claims_prod_ready(self):
        inventory={
            "api_routes":["/api/login","/api/logout","/api/status"],
            "server_sha256":"a"*64,"frontend_sha256":"b"*64,
            "auth_hooks":["check_session","do_GET","do_POST"],
        }
        assessment={"adapter_design_ready":False,
                    "source_hashes_match":False,
                    "missing_known_routes":["/api/nat/add"],
                    "unexpected_route_count":1}
        handler={
            "candidate_count":1,"unclassified_count":0,
            "handler_candidates":[{
                "verbs":["GET","POST"],"has_check_session_method":True,
                "conditional_routes":{"GET":["/api/status"],"POST":["/api/nat/add"]},
                "reachable_call_counts":{"GET":{"check_session":1},"POST":{"check_session":1}}
            }]
        }
        service={"inspection":"structural","web_user_expected":True,
                 "auth_store_write_scope_declared":False}
        with patch.object(preflight,"inspect",return_value=inventory),\
             patch.object(preflight,"_load_json",return_value={}),\
             patch.object(preflight,"assess",return_value=assessment),\
             patch.object(preflight,"audit",return_value=handler),\
             patch.object(preflight,"_auth_directory",return_value={
                 "state":"not_initialized","requires_private_storage_setup":True
             }):
            report=preflight.summarize(
                Path("/private/backend/server.py"),
                Path("/private/web/app.js"),Path("/private/baseline.json"),
                unit_checker=lambda:service,
                login_checker=lambda:{"inspection":"structural","http_basic_declared":True})
        self.assertFalse(report["production_cutover_ready"])
        self.assertFalse(report["baseline_backend_matches"])
        self.assertFalse(report["baseline_frontend_matches"])
        self.assertFalse(report["live_code_exported"])
        self.assertFalse(report["secret_values_exported"])
        self.assertIn("live_source_not_identical_to_reviewed_baseline",report["blockers"])
        self.assertIn("auth_store_not_in_web_service_writable_paths",report["blockers"])
        self.assertIn("auth_store_not_prepared_with_private_permissions",report["blockers"])
        serialized=json.dumps(report)
        for value in ("PRIVATE-KEY-DO-NOT-EXPOSE","password", "54.37.165.151",
                      "/private/backend/server.py","/private/web/app.js","peer-secret"):
            self.assertNotIn(value,serialized)

    def test_private_storage_check_does_not_create_any_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            missing=root/"not-created"
            self.assertTrue(preflight._auth_directory(missing)["requires_private_storage_setup"])
            self.assertFalse(missing.exists())
            safe=root/"safe"
            safe.mkdir(mode=0o700)
            safe.chmod(0o700)
            self.assertFalse(preflight._auth_directory(
                safe,expected_uid=__import__('os').getuid())["requires_private_storage_setup"])
            self.assertTrue(preflight._auth_directory(
                safe,expected_uid=__import__('os').getuid()+1)["requires_private_storage_setup"])
            safe.chmod(0o755)
            self.assertEqual(preflight._auth_directory(safe)["state"],"unsafe_permissions")
            safe.chmod(0o700)
            alias=root/"alias"
            alias.symlink_to(safe,target_is_directory=True)
            self.assertEqual(preflight._auth_directory(alias)["state"],"unsafe_permissions")

    def test_systemd_properties_are_allowlisted(self):
        fake=lambda cmd,**kwargs: SimpleNamespace(returncode=0,stdout=(
            b"User=ceratonet\nProtectSystem=strict\nProtectHome=yes\n"
            b"PrivateTmp=yes\nNoNewPrivileges=no\n"
            b"ReadWritePaths=/var/lib/cerato-network-updates\n"
            b"Environment=PRIVATE_PASSWORD=do-not-print\n"
            b"ExecStart=/usr/bin/private-command --secret=qwerty\n"))
        result=preflight._systemd_unit(runner=fake)
        self.assertTrue(result["web_user_expected"])
        self.assertFalse(result["auth_store_write_scope_declared"])
        self.assertNotIn("PRIVATE_PASSWORD",json.dumps(result))
        self.assertNotIn("ExecStart",json.dumps(result))

    def test_git_source_contains_no_active_restart_or_install(self):
        text=(ROOT/"integrations/preflight_native_auth.py").read_text()
        for forbidden in ("systemctl restart","chmod(","chown(","mkdir(","os.system(",
                          "apt install","git pull","nginx -s reload",
                          "wg set","iptables ","nft ","curl ","ssh "):
            self.assertNotIn(forbidden,text)


if __name__=="__main__":
    unittest.main()

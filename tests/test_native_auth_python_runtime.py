"""Isolated crypto runtime never changes OVH Web, auth DB or the OS Python."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import prepare_native_auth_python_runtime as m

class IsolatedRuntimeTests(unittest.TestCase):
    def test_approved_cryptographic_requirements_are_exact(self):
        self.assertEqual(m.EXPECTED_REQUIREMENTS,
            b"argon2-cffi>=25.1,<26\ncryptography>=44,<48\n")
        self.assertEqual((ROOT/"security/requirements.txt").read_bytes(),
                         m.EXPECTED_REQUIREMENTS)
        self.assertNotIn("system_site_packages=True",m.SMOKE)
        self.assertIn("PasswordHasher",m.SMOKE)
        self.assertIn("AESGCM",m.SMOKE)
        self.assertIn("approved_packages_only",m.SMOKE)

    def test_untrusted_existing_environment_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as t:
            target=Path(t)/"native-auth-venv"
            target.mkdir()
            (target/"surprise").write_text("do not overwrite")
            with patch.object(m,"DEST",target), \
                 patch.object(m,"trusted_root"), \
                 patch.object(m,"ensure_host"), \
                 patch.object(m,"check_runtime",side_effect=m.RuntimePreparationError("untrusted")):
                with self.assertRaises(m.RuntimePreparationError):
                    m.install()
            self.assertEqual((target/"surprise").read_text(),"do not overwrite")

    def test_missing_python_venv_fails_without_installing_os_packages(self):
        with tempfile.TemporaryDirectory() as t:
            target=Path(t)/"native-auth-venv"
            old={"status":"runtime_missing","venv_module_available":False}
            with patch.object(m,"DEST",target), \
                 patch.object(m,"state",return_value=old), \
                 patch.object(m,"call") as runner:
                with self.assertRaisesRegex(m.RuntimePreparationError,"python3-venv"):
                    m.install()
                runner.assert_not_called()
            self.assertFalse(target.exists())

    def test_new_venv_is_verified_as_ceratonet_before_atomic_activation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            dest=root/"native-auth-venv"
            requirements=root/"requirements.txt"
            requirements.write_bytes(m.EXPECTED_REQUIREMENTS)
            all_calls=[]
            def fake_call(args,**kw):
                all_calls.append(args)
                if args[:3]==[m.PYTHON,"-m","venv"] and len(args)==4:
                    venv=Path(args[3])
                    (venv/"bin").mkdir()
                    (venv/"bin/python").write_text("#!/bin/sh\nexit 0\n")
                    (venv/"pyvenv.cfg").write_text(
                        "include-system-site-packages = false\n")
                    return SimpleNamespace(returncode=0,stdout="",stderr="")
                if len(args)>2 and args[1:3]==["-m","pip"]:
                    return SimpleNamespace(returncode=0,stdout="",stderr="")
                if args[0]==m.RUNUSER:
                    return SimpleNamespace(returncode=0,stdout=json.dumps({
                        "argon2_version":"25.1.0","cryptography_version":"46.0.2",
                        "argon2id_checked":True,"aes_gcm_checked":True,
                        "approved_packages_only":True}),stderr="")
                raise AssertionError("Unexpected command "+repr(args))
            account=SimpleNamespace(pw_uid=1001,pw_gid=1001)
            root.mkdir(exist_ok=True)
            with patch.object(m,"ROOT",root), \
                 patch.object(m,"DEST",dest), \
                 patch.object(m,"REQUIREMENTS",requirements), \
                 patch.object(m,"state",return_value={
                     "status":"runtime_missing","venv_module_available":True}), \
                 patch.object(m,"call",side_effect=fake_call), \
                 patch.object(m,"root_owned_venv",return_value=True), \
                 patch.object(m,"trusted_venv_config",return_value=True), \
                 patch.object(m.pwd,"getpwnam",return_value=account):
                result=m.install()
            self.assertEqual(result["status"],"runtime_ready_inactive")
            self.assertTrue(result["runtime_created"])
            self.assertTrue(result["usable_by_web_user"])
            self.assertFalse(result["native_auth_activated"])
            self.assertFalse(result["production_modified"])
            self.assertFalse(result["service_restarted"])
            self.assertFalse(result["network_modified"])
            self.assertFalse(result["accounts_created"])
            self.assertTrue(dest.exists())
            self.assertIn("include-system-site-packages = false",
                          (dest/"pyvenv.cfg").read_text())
            installs=[x for x in all_calls if len(x)>2 and x[1:3]==["-m","pip"]]
            self.assertEqual(len(installs),1)
            self.assertIn("--only-binary=:all:",installs[0])
            self.assertIn("--no-cache-dir",installs[0])
            self.assertIn("--isolated",installs[0])
            self.assertFalse(any("apt" in str(x) or "systemctl" in str(x)
                                 for x in all_calls))

    def test_failed_package_install_does_not_leave_partial_venv(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            dest=root/"native-auth-venv"
            requirements=root/"requirements.txt"
            requirements.write_bytes(m.EXPECTED_REQUIREMENTS)
            def fake_call(args,**kw):
                if args[:3]==[m.PYTHON,"-m","venv"]:
                    (Path(args[3])/"bin").mkdir()
                    (Path(args[3])/"bin/python").write_text("python")
                    return SimpleNamespace(returncode=0)
                if len(args)>2 and args[1:3]==["-m","pip"]:
                    return SimpleNamespace(returncode=1)
                raise AssertionError(args)
            with patch.object(m,"ROOT",root), \
                 patch.object(m,"DEST",dest), \
                 patch.object(m,"REQUIREMENTS",requirements), \
                 patch.object(m,"state",return_value={
                    "status":"runtime_missing","venv_module_available":True}), \
                 patch.object(m,"call",side_effect=fake_call):
                with self.assertRaisesRegex(m.RuntimePreparationError,"roues Python"):
                    m.install()
            self.assertFalse(dest.exists())
            self.assertFalse(list(root.glob(".native-auth-venv-staging.*")))

if __name__=="__main__":
    unittest.main()

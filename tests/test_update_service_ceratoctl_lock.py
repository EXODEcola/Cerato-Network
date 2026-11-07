"""Only the existing ceratoctl lock is writable inside Web updater sandbox."""
from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import fix_update_service_ceratoctl_lock as lockfix

class ScopedLockTests(unittest.TestCase):
    def test_dropin_whitelists_exact_lockfile_only(self):
        config=lockfix.DROPIN_TEXT
        self.assertIn("[Service]",config)
        self.assertIn("ReadWritePaths=/etc/cerato-network/.ceratoctl.lock",config)
        for blocked in ("ReadWritePaths=/etc/cerato-network\n",
                        "ProtectSystem=false","ProtectSystem=off",
                        "NoNewPrivileges=no","/etc/wireguard"):
            self.assertNotIn(blocked,config)
        self.assertNotIn("wg set",config)
        self.assertNotIn("nft",config)

    def test_preflight_reproduces_hardened_context_and_scopes_writes(self):
        def fake_command(*args,**kwargs):
            self.assertEqual(args[0],"systemd-run")
            self.assertIn("ProtectSystem=strict",args)
            self.assertIn("NoNewPrivileges=yes",args)
            self.assertIn("ProtectHome=yes",args)
            allow=[v for v in args if v.startswith("ReadWritePaths=")]
            self.assertEqual(len(allow),1)
            self.assertIn("/etc/cerato-network/.ceratoctl.lock",allow[0])
            self.assertNotIn("/etc/cerato-network/config.json",allow[0])
            return SimpleNamespace(returncode=0,
                stdout="Statut Cerato valide sous sandbox systemd : True\n")
        with patch.object(lockfix,"command",side_effect=fake_command):
            self.assertTrue(lockfix.transient_test())

    def test_failed_transient_preflight_stops_without_write(self):
        with patch.object(lockfix,"command",
                          return_value=SimpleNamespace(returncode=4,stdout="")), \
             patch.object(lockfix,"install_dropin") as install:
            with self.assertRaises(lockfix.LockRepairError):
                lockfix.transient_test()
            install.assert_not_called()

    def test_install_creates_only_unit_override_idempotently(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"override"/"60-lock.conf"
            with patch.object(lockfix,"DROPIN",path), \
                 patch.object(lockfix,"_trusted_dir",return_value=True), \
                 patch.object(lockfix,"command",return_value=SimpleNamespace(returncode=0)), \
                 patch.object(lockfix,"unit_state",return_value={
                     "ReadWritePaths":lockfix.SANDBOX_WRITABLE}):
                self.assertTrue(lockfix.install_dropin())
                self.assertFalse(lockfix.install_dropin())
                self.assertEqual(path.read_text(),lockfix.DROPIN_TEXT)
                self.assertFalse((path.parent/"config.json").exists())

    def test_installer_refuses_wrong_signed_release(self):
        bad={"installed_version":"v0.1.0-beta.1",
             "available_version":"v0.1.2-beta.1",
             "installable":True,"channel":"beta"}
        with patch.object(lockfix,"updater_status",return_value=bad), \
             patch.object(lockfix,"command") as runner:
            with self.assertRaises(lockfix.LockRepairError):
                lockfix.apply_existing_signed_release()
            runner.assert_not_called()

    def test_updater_starts_only_after_exact_release_preflight(self):
        data=[
            {"installed_version":"v0.1.0-beta.1",
             "available_version":"v0.1.1-beta.1",
             "installable":True,"channel":"beta"},
            {"installed_version":"v0.1.1-beta.1"},
        ]
        calls=[]
        def fake_command(*args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0)
        with patch.object(lockfix,"updater_status",side_effect=data), \
             patch.object(lockfix,"command",side_effect=fake_command):
            result=lockfix.apply_existing_signed_release()
        self.assertEqual(result["result"],"installed")
        self.assertTrue(any(c[0:2]==("systemctl","start") for c in calls))
        self.assertFalse(any(c[1]=="stop" for c in calls))

if __name__=="__main__":
    unittest.main()

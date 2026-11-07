"""Native auth host setup: exact pinned RISE-1 source, no cutover or network mutation."""
from __future__ import annotations
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import prepare_native_auth_host as m

class NativeHostPrerequisitesTests(unittest.TestCase):
    def test_dropin_is_scoped_to_empty_account_store_only(self):
        text=m.DROPIN.decode()
        self.assertEqual(text.count("ReadWritePaths="),1)
        self.assertIn("ReadWritePaths=/var/lib/cerato-network-auth",text)
        self.assertIn("Environment=CERATO_WEB_ORIGIN=https://51.210.223.57",text)
        for forbidden in ("/etc/wireguard","wg-cerato","nft","/etc/cerato-network",
                          "ProtectSystem=off","NoNewPrivileges=false","ExecStart=",
                          "Restart=","ProtectHome=no"):
            self.assertNotIn(forbidden,text)

    def test_dependencies_do_not_install_packages(self):
        result=m.dependency_status()
        self.assertEqual(set(result),{"argon2","cryptography"})
        self.assertIn("meets_pinned_requirements",result["argon2"])

    def test_file_pin_checks_all_three_hashes(self):
        self.assertEqual(set(m.EXPECTED),{
            "/opt/cerato-network/backend/server.py",
            "/opt/cerato-network/web/app.js",
            "/opt/cerato-network/web/style.css",
        })
        self.assertTrue(all(len(value)==64 for value in m.EXPECTED.values()))

    def test_install_only_adds_one_systemd_override_and_private_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            store=root/"cerato-network-auth"
            directory=root/"units"
            directory.mkdir()
            config=directory/"70-cerato-native-auth.conf"
            commands=[]
            uid=os.geteuid()
            gid=os.getegid()
            account=SimpleNamespace(pw_uid=uid,pw_gid=gid)
            returns={
                "source_fingerprints_match":True,
                "installed_version":"v0.1.2-beta.1",
                "storage_directory_ready":False,
                "systemd_dropin_present":False,
                "service_uses_strict_filesystem":True,
                "origin_expected":m.ORIGIN,
                "dependency_status":{"argon2":{"meets_pinned_requirements":False},
                                     "cryptography":{"meets_pinned_requirements":True}},
                "network_modified":False,"live_auth_activated":False,
            }
            def calls(*args,**kwargs):
                commands.append(args)
                return SimpleNamespace(returncode=0,stdout="")
            def properties():
                return {
                    "ReadWritePaths":str(store),
                    "Environment":"CERATO_WEB_ORIGIN="+m.ORIGIN,
                }
            with patch.object(m,"STORE",store),patch.object(m,"CONF",config), \
                 patch.object(m,"preflight",return_value=returns), \
                 patch.object(m,"unit_context",side_effect=properties), \
                 patch.object(m.pwd,"getpwnam",return_value=account), \
                 patch.object(m,"process",side_effect=calls):
                outcome=m.install()
            self.assertEqual(outcome["result"],"prepared_inactive")
            self.assertTrue(store.is_dir())
            self.assertEqual(stat.S_IMODE(store.stat().st_mode),0o700)
            self.assertEqual(config.read_bytes(),m.DROPIN)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode),0o644)
            self.assertFalse(outcome["db_initialized"])
            self.assertFalse(outcome["service_restarted"])
            self.assertFalse(outcome["network_modified"])
            self.assertFalse(outcome["live_auth_activated"])
            self.assertEqual(commands,[("systemctl","daemon-reload")])

    def test_reject_different_existing_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"system"
            folder.mkdir()
            existing=folder/"70-cerato-native-auth.conf"
            existing.write_text("ReadWritePaths=/etc\n")
            with patch.object(m,"CONF",existing):
                with self.assertRaises(m.PrerequisiteError):
                    m.dropin_state()

    def test_pin_mismatch_blocks_any_changes(self):
        with patch.object(m,"pinned_sources",side_effect=m.PrerequisiteError(
                          "Empreinte différente")), \
             patch.object(m,"unit_context") as unit, \
             self.assertRaises(m.PrerequisiteError):
            m.preflight()
            unit.assert_not_called()

if __name__=="__main__":
    unittest.main()

"""Non-activating, reversible-by-rmdir native auth directory preparation."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from prepare_private_auth_storage import StoragePreparationError, provision

class PrivateStorageProvisioningTests(unittest.TestCase):
    def test_check_does_not_create_and_install_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/"cerato-network-auth"
            uid,gid=os.geteuid(),os.getegid()
            checked=provision(target,uid=uid,gid=gid)
            self.assertEqual(checked["state"],"not_initialized")
            self.assertFalse(checked["created"])
            self.assertFalse(target.exists())
            installed=provision(target,uid=uid,gid=gid,install=True)
            self.assertTrue(installed["created"])
            self.assertFalse(installed["account_initialized"])
            self.assertFalse(installed["network_modified"])
            self.assertFalse(installed["web_service_modified"])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o700)
            self.assertEqual([p.name for p in target.iterdir()],[])
            again=provision(target,uid=uid,gid=gid,install=True)
            self.assertFalse(again["created"])

    def test_misconfigured_existing_directory_denied_not_changed(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"cerato-network-auth"
            target.mkdir(mode=0o755)
            target.chmod(0o755)
            with self.assertRaisesRegex(StoragePreparationError,"non privé"):
                provision(target,uid=os.geteuid(),gid=os.getegid(),install=True)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)
            target.chmod(0o700)
            with self.assertRaisesRegex(StoragePreparationError,"non privé"):
                provision(target,uid=os.geteuid()+1,gid=os.getegid(),install=True)
            self.assertEqual(target.stat().st_uid,os.geteuid())

    def test_symlinks_and_unreviewed_paths_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"real").mkdir(mode=0o700)
            (root/"real").chmod(0o700)
            (root/"link").symlink_to(root/"real",target_is_directory=True)
            with self.assertRaises(StoragePreparationError):
                provision(root/"link"/"cerato-network-auth",uid=os.geteuid(),gid=os.getegid(),install=True)
            (root/"cerato-network-auth").symlink_to(root/"real",target_is_directory=True)
            with self.assertRaises(StoragePreparationError):
                provision(root/"cerato-network-auth",uid=os.geteuid(),gid=os.getegid(),install=True)
            with self.assertRaises(StoragePreparationError):
                provision(root/"network-config",uid=os.geteuid(),gid=os.getegid(),install=True)

    def test_wrong_group_refused_without_chown(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/"cerato-network-auth"
            target.mkdir(mode=0o700)
            target.chmod(0o700)
            with self.assertRaises(StoragePreparationError):
                provision(target,uid=os.geteuid(),gid=os.getegid()+1,install=True)
            self.assertEqual(target.stat().st_gid,os.getegid())

    def test_no_migration_or_service_mutation_implemented(self):
        code=(ROOT/"integrations/prepare_private_auth_storage.py").read_text()
        for unsafe in ("AuthStore(", "issue_bootstrap_token(", "setup_owner(",
                       "systemctl restart","systemctl daemon-reload",
                       "chmod -R","chown -R","/etc/wireguard/",
                       "iptables ","nft ","subprocess.run(","nginx -s",
                       "os.system(","sqlite3.connect("):
            self.assertNotIn(unsafe,code)
        self.assertIn('STORE=ROOT/"cerato-network-auth"',code)

if __name__=="__main__":
    unittest.main()

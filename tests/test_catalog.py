"""Signed-release catalog tests: no remote downloads or network mutations."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"updates"))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from build_release import build
from catalog import release_info

class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.src=root/"src"
        self.src.mkdir()
        (self.src/"README.md").write_text("Cerato Network",encoding="utf8")
        (self.src/"LICENSE").write_text("MIT",encoding="utf8")
        self.release=root/"distribution"
        self.key=root/"signing.pem"
        self.public=root/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.key)],
                       capture_output=True,check=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout","-out",str(self.public)],
                       capture_output=True,check=True)

    def test_unconfigured_is_not_installable(self):
        result=release_info()
        self.assertFalse(result["configured"])
        self.assertFalse(result["verified"])
        self.assertFalse(result["install_enabled"])

    def test_valid_signed_stable_and_beta_policy(self):
        build(self.src,self.release,"v1.0.0-beta.1",self.key)
        stable=release_info(str(self.release),str(self.public),"v0.9.0","stable")
        self.assertFalse(stable["verified"])
        beta=release_info(str(self.release),str(self.public),"v0.9.0","beta")
        self.assertTrue(beta["verified"])
        self.assertEqual(beta["available_version"],"v1.0.0-beta.1")
        self.assertFalse(beta["install_enabled"])

    def test_corrupt_archive_is_rejected(self):
        build(self.src,self.release,"v1.0.0",self.key)
        file=self.release/"cerato-network-release.zip"
        file.write_bytes(file.read_bytes()+b"tampered")
        result=release_info(str(self.release),str(self.public),"v0.9.0","stable")
        self.assertFalse(result["verified"])
        self.assertFalse(result["install_enabled"])

if __name__=="__main__":
    unittest.main()

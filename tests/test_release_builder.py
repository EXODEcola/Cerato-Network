"""Run on CERATO-BUILD-01 with OpenSSL; no GitHub Actions required."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_release import build, verify, PackageError

class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/"source"
        self.source.mkdir()
        (self.source/"LICENSE").write_text("MIT")
        (self.source/"README.md").write_text("Project")
        (self.source/"main.py").write_text("print('hello')")
        self.out=self.root/"dist"
        self.key=self.root/"signing.key"
        self.pub=self.root/"verify.pub"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.key)],
                       check=True,capture_output=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout","-out",str(self.pub)],
                       check=True,capture_output=True)

    def test_signed_artifact_and_manifest(self):
        manifest=build(self.source,self.out,"v0.1.0",self.key)
        self.assertEqual(manifest["version"],"v0.1.0")
        self.assertEqual(verify(self.out,self.pub)["sha256"],manifest["sha256"])

    def test_tampered_archive_is_rejected(self):
        build(self.source,self.out,"v0.1.0",self.key)
        with (self.out/"cerato-network-release.zip").open("ab") as file:
            file.write(b"tampered")
        with self.assertRaises(PackageError):
            verify(self.out,self.pub)

    def test_tampered_manifest_is_rejected(self):
        build(self.source,self.out,"v0.1.0",self.key)
        path=self.out/"manifest.json"
        data=json.loads(path.read_text())
        data["version"]="v1.0.0"
        path.write_text(json.dumps(data))
        with self.assertRaises(PackageError):
            verify(self.out,self.pub)

    def test_refuses_secrets_and_symlinks(self):
        (self.source/".env").write_text("SECRET=abc")
        (self.source/"wg-cerato.conf").write_text("PrivateKey=secret")
        build(self.source,self.out,"v0.1.1-beta.1",self.key)
        self.assertEqual(verify(self.out,self.pub)["version"],"v0.1.1-beta.1")
        (self.source/"linked").symlink_to(self.source/"main.py")
        with self.assertRaises(PackageError):
            build(self.source,self.root/"dist2","v0.1.2",self.key)

    def test_private_key_requires_0600(self):
        os.chmod(self.key,0o644)
        with self.assertRaises(PackageError):
            build(self.source,self.out,"v0.1.0",self.key)

if __name__=="__main__":
    unittest.main()

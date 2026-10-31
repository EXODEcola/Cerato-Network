"""Cerato Network external VPS release pipeline tests (no GitHub Actions)."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from release_pipeline import prepare, sign_prepared, verify_prepared
from build_release import PackageError


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.src=root/"checkout"
        self.src.mkdir()
        (self.src/"LICENSE").write_text("MIT",encoding="utf8")
        (self.src/"README.md").write_text("# Cerato Network",encoding="utf8")
        (self.src/"web").mkdir()
        (self.src/"web"/"index.html").write_text("<h1>safe</h1>",encoding="utf8")
        (self.src/".env").write_text("SECRET=never package this",encoding="utf8")
        self.output=root/"unsigned"
        self.key=root/"ed25519.key"
        self.pub=root/"ed25519.pub"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.key)],
                       check=True,capture_output=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout","-out",str(self.pub)],
                       check=True,capture_output=True)

    def test_prepare_sign_verify_and_repeat_rejected(self):
        unsigned=prepare(self.src,self.output,"v0.3.0-beta.1")
        self.assertEqual(unsigned["version"],"v0.3.0-beta.1")
        self.assertFalse((self.output/"manifest.sig").exists())
        with zipfile.ZipFile(self.output/"cerato-network-release.zip") as arc:
            self.assertIn("cerato-network/web/index.html",arc.namelist())
            self.assertNotIn("cerato-network/.env",arc.namelist())
        with self.assertRaises(OSError):
            verify_prepared(self.output,self.pub)
        signed=sign_prepared(self.output,self.key)
        self.assertEqual(signed["sha256"],unsigned["sha256"])
        self.assertEqual(verify_prepared(self.output,self.pub)["version"],"v0.3.0-beta.1")
        with self.assertRaises(PackageError):
            sign_prepared(self.output,self.key)
        with self.assertRaises(PackageError):
            prepare(self.src,self.output,"v0.3.0-beta.1")

    def test_modified_unsigned_archive_is_not_signed(self):
        prepare(self.src,self.output,"v0.3.0")
        with (self.output/"cerato-network-release.zip").open("ab") as file:
            file.write(b"tampered")
        with self.assertRaises(PackageError):
            sign_prepared(self.output,self.key)
        self.assertFalse((self.output/"manifest.sig").exists())

    def test_modified_manifest_is_not_signed(self):
        prepare(self.src,self.output,"v0.3.0")
        manifest=self.output/"manifest.json"
        metadata=json.loads(manifest.read_text(encoding="utf8"))
        metadata["version"]="v9.0.0"
        manifest.write_text(json.dumps(metadata),encoding="utf8")
        with self.assertRaises(PackageError):
            sign_prepared(self.output,self.key)

    def test_unsigned_archives_are_deterministic(self):
        one=prepare(self.src,self.output,"v0.3.0")
        two=prepare(self.src,Path(self.temp.name)/"second","v0.3.0")
        self.assertEqual(one["sha256"],two["sha256"])

    def test_insecure_private_key_is_rejected(self):
        prepare(self.src,self.output,"v0.3.0")
        os.chmod(self.key,0o644)
        with self.assertRaises(PackageError):
            sign_prepared(self.output,self.key)


if __name__ == "__main__":
    unittest.main()

"""End-to-end fake signed visual release -> verified static publication stage.

All keys are ephemeral test fixtures, never production signing credentials.
"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from release_pipeline import prepare, sign_prepared
from channel_index import create_channel
from stage_signed_static_release import stage, StagePublicationError
from build_release import PackageError


class SignedStaticStageTests(unittest.TestCase):
    def fixture(self,root):
        root=Path(root)
        src=root/"src"
        src.mkdir()
        (src/"LICENSE").write_text("MIT test license",encoding="utf8")
        (src/"README.md").write_text("Synthetic test only",encoding="utf8")
        web=src/"live-overlay"/"web"
        web.mkdir(parents=True)
        (web/"app.js").write_text("console.log('trusted');\n",encoding="utf8")
        (web/"style.css").write_text("body{background:#111}\n",encoding="utf8")
        (src/"live-overlay"/"compat.json").write_text(
            json.dumps({"schema":"cerato-network-legacy-web-visual-v1",
                        "target":"cerato-network-web-8787",
                        "from_versions":["v0.0.0"]})+"\n",encoding="utf8")
        keys=root/"signer"
        keys.mkdir()
        private=keys/"private.pem"
        public=keys/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                        "-out",str(private)],capture_output=True,check=True)
        subprocess.run(["openssl","pkey","-in",str(private),"-pubout",
                        "-out",str(public)],capture_output=True,check=True)
        private.chmod(0o600)
        release=root/"approved"/"v0.1.0-beta.1"
        release.mkdir(parents=True,mode=0o700)
        release.chmod(0o700)
        prepare(src,release,"v0.1.0-beta.1")
        sign_prepared(release,private)
        channel=root/"approved"/"channels"
        create_channel(release,"beta",channel,private,public,issued_at=int(time.time()))
        return release,channel,public

    def test_publishes_only_approved_signed_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            release,channel,key=self.fixture(root)
            out=root/"public-ready"
            info=stage(release,channel,key,"beta",out)
            self.assertTrue(info["signature_verified"])
            self.assertTrue(info["visual_only"])
            self.assertFalse(info["published_to_ovh"])
            self.assertFalse(info["private_key_processed"])
            self.assertEqual(set(info["files"]),{
                "channels/beta.json","channels/beta.sig",
                "releases/v0.1.0-beta.1/manifest.json",
                "releases/v0.1.0-beta.1/manifest.sig",
                "releases/v0.1.0-beta.1/cerato-network-release.zip",
            })
            self.assertEqual((out/"channels"/"beta.json").read_bytes(),
                             (channel/"beta.json").read_bytes())

    def test_tampered_channel_rejected_before_any_file_created(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            release,channel,key=self.fixture(root)
            with (channel/"beta.json").open("ab") as fh:
                fh.write(b"tampered")
            out=root/"public-ready"
            with self.assertRaises((ValueError,StagePublicationError,PackageError)):
                stage(release,channel,key,"beta",out)
            self.assertFalse(out.exists())

    def test_expired_index_and_unsigned_release_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            release,channel,key=self.fixture(root)
            with self.assertRaises(StagePublicationError):
                stage(release,channel,key,"beta",root/"out",now=int(time.time())+90000)
            self.assertFalse((root/"out").exists())
            (release/"manifest.sig").unlink()
            with self.assertRaises((ValueError,OSError)):
                stage(release,channel,key,"beta",root/"out")
            self.assertFalse((root/"out").exists())


if __name__=="__main__":
    unittest.main()

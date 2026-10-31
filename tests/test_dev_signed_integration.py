"""True ephemeral Ed25519 Dev pipeline integration (no production signing key)."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "updates"))
from release_pipeline import prepare, sign_prepared
from channel_index import create_channel
from stage_signed_static_release import stage, StagePublicationError
from build_release import PackageError


def fixture(root):
    src = root / "src"
    (src / "live-overlay" / "web").mkdir(parents=True)
    (src / "LICENSE").write_text("MIT - test fixture", encoding="utf-8")
    (src / "README.md").write_text("Ephemeral Dev test", encoding="utf-8")
    (src / "live-overlay" / "web" / "style.css").write_text(
        "body { color: #eee }\n", encoding="utf-8")
    (src / "live-overlay" / "web" / "app.js").write_text(
        "console.log('test');\n", encoding="utf-8")
    (src / "live-overlay" / "compat.json").write_text(
        json.dumps({
            "schema": "cerato-network-legacy-web-visual-v1",
            "target": "cerato-network-web-8787",
            "from_versions": ["v0.1.0-beta.1"],
        }) + "\n", encoding="utf-8")
    keydir = root / "signer"
    keydir.mkdir()
    private, public = keydir / "private.pem", keydir / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                    "-out", str(private)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private),
                    "-pubout", "-out", str(public)], check=True,
                   capture_output=True)
    private.chmod(0o600)
    release = root / "approved" / "v0.1.1-dev.1"
    release.mkdir(mode=0o700, parents=True)
    release.chmod(0o700)
    prepare(src, release, "v0.1.1-dev.1")
    sign_prepared(release, private)
    channels = root / "approved" / "channels"
    create_channel(release, "dev", channels, private, public,
                   issued_at=int(time.time()), validity_seconds=604800)
    return release, channels, public, private


class DevIntegrationTests(unittest.TestCase):
    def test_dev_signed_artifact_is_staged_with_real_signature(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            release, channels, public, private = fixture(root)
            result = stage(release, channels, public, "dev", root / "public")
            self.assertTrue(result["signature_verified"])
            self.assertTrue(result["visual_only"])
            self.assertFalse(result["published_to_ovh"])
            self.assertTrue((root / "public" / "channels" / "dev.json").exists())
            self.assertFalse((root / "public" / "channels" / "beta.json").exists())
            self.assertFalse((root / "public" / "private.pem").exists())

    def test_signed_dev_release_does_not_publish_on_beta_or_stable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            release, channels, public, private = fixture(root)
            with self.assertRaises((PackageError, StagePublicationError)):
                create_channel(release, "stable", root / "other",
                               private, public)
            with self.assertRaises((StagePublicationError, OSError, ValueError)):
                stage(release, channels, public, "beta", root / "out")
            self.assertFalse((root / "out").exists())

    def test_corrupted_dev_index_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            release, channels, public, private = fixture(root)
            with (channels / "dev.json").open("ab") as out:
                out.write(b"tampered")
            with self.assertRaises((StagePublicationError, ValueError, PackageError)):
                stage(release, channels, public, "dev", root / "out")
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()

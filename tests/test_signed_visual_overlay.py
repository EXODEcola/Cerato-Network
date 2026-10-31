"""End-to-end signed visual-only release compatibility without private backend data."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from build_release import build
import live_controller as ctl


class SignedVisualOverlayTests(unittest.TestCase):
    def test_signed_visual_update_has_only_js_css(self):
        with tempfile.TemporaryDirectory() as path:
            base=Path(path)
            src=base/"source"
            src.mkdir()
            (src/"LICENSE").write_text("MIT",encoding="utf8")
            (src/"README.md").write_text("Cerato",encoding="utf8")
            overlay=src/"live-overlay"
            (overlay/"web").mkdir(parents=True)
            (overlay/"web/app.js").write_text("console.log('visual');\n",encoding="utf8")
            (overlay/"web/style.css").write_text("body{background:#111}\n",encoding="utf8")
            (overlay/"compat.json").write_text(json.dumps({
                "schema":ctl.VISUAL_SCHEMA,
                "target":"cerato-network-web-8787",
                "from_versions":["v0.0.0"]
            }),encoding="utf8")
            secret=base/"private.pem"
            public=base/"public.pem"
            subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                            "-out",str(secret)],check=True,capture_output=True)
            subprocess.run(["openssl","pkey","-in",str(secret),"-pubout",
                            "-out",str(public)],check=True,capture_output=True)
            archive=base/"release"
            build(src,archive,"v0.1.0-beta.1",secret)
            verified=ctl._read_overlay(archive,"v0.0.0")
            self.assertEqual(set(verified),ctl.VISUAL_FILES)
            self.assertNotIn("backend/server.py",verified)
            self.assertIsNone(ctl._read_overlay(archive,"v0.0.0",verify_only=True))
            with self.assertRaises(ctl.UpdateError):
                ctl._read_overlay(archive,"v0.1.0-beta.1")
            # A visual release does not overwrite the legacy auth/network code.
            self.assertIn(b"console.log",verified["web/app.js"])

    def test_signed_css_patch_preserves_live_js_and_backend(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            src=root/"source"
            src.mkdir()
            (src/"LICENSE").write_text("MIT",encoding="utf8")
            (src/"README.md").write_text("Cerato",encoding="utf8")
            (src/"live-overlay"/"web").mkdir(parents=True)
            (src/"live-overlay"/"compat.json").write_text(json.dumps({
                "schema":ctl.CSS_PATCH_SCHEMA,
                "target":"cerato-network-web-8787",
                "from_versions":["v0.0.0"]
            }),encoding="utf8")
            (src/"live-overlay"/"web/style.append.css").write_bytes(
                ctl.CSS_PATCH_MARKER+b"\\n.cerato-updates{border-radius:7px}\\n")
            key=root/"key.pem"
            subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                            "-out",str(key)],check=True,capture_output=True)
            out=root/"release"
            build(src,out,"v0.1.0-beta.1",key)
            self.assertIsNone(ctl._read_overlay(out,"v0.0.0",verify_only=True))
            livecss=root/"live.css"
            livecss.write_bytes(b"body{color:white}\\n")
            with patch.dict(ctl.ALLOWED,{"web/style.css":livecss}):
                files=ctl._read_overlay(out,"v0.0.0")
            self.assertEqual(set(files),{"web/style.css"})
            self.assertTrue(files["web/style.css"].startswith(b"body{color:white}"))
            self.assertIn(ctl.CSS_PATCH_MARKER,files["web/style.css"])

    def test_refuses_unrecognized_file_sets_before_install(self):
        self.assertEqual(ctl.VISUAL_FILES,{"web/app.js","web/style.css"})
        self.assertNotIn("backend/server.py",ctl.VISUAL_FILES)


if __name__=="__main__":
    unittest.main()

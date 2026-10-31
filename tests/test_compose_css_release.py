"""CSS-only first public release cannot overwrite Cerato Network backend/JS."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from compose_css_release import compose, CSSReleaseError,MARKER
from release_pipeline import prepare


class CSSFirstReleaseTests(unittest.TestCase):
    def test_can_prepare_a_compatible_additive_release_without_live_source(self):
        with tempfile.TemporaryDirectory() as p:
            base=Path(p)
            out=base/"release-source"
            out.mkdir()
            (out/"LICENSE").write_text("MIT",encoding="utf8")
            (out/"README.md").write_text("Official safe CSS-only release",encoding="utf8")
            result=compose(ROOT/"release-assets/graphite-operations.css",out/"live-overlay",["v0.0.0"])
            self.assertFalse(result["backend_included"])
            self.assertFalse(result["frontend_js_included"])
            self.assertEqual(list((out/"live-overlay"/"web").iterdir())[0].name,"style.append.css")
            manifest=prepare(out,base/"prepared","v0.1.0-beta.1")
            self.assertEqual(manifest["version"],"v0.1.0-beta.1")

    def test_rejects_non_whitelisted_or_replayed_css(self):
        with tempfile.TemporaryDirectory() as p:
            base=Path(p)
            bad=base/"danger.css"
            bad.write_bytes(MARKER+b'\n@import "https://evil.example/a.css";')
            with self.assertRaises(CSSReleaseError):
                compose(bad,base/"out",["v0.0.0"])
            self.assertFalse((base/"out").exists())
            with self.assertRaises(CSSReleaseError):
                compose(ROOT/"release-assets/graphite-operations.css",base/"out",["bad version"])
            self.assertFalse((base/"out").exists())


if __name__=="__main__":
    unittest.main()

"""UI-only overlay preparation using synthetic audited source fixtures."""
from __future__ import annotations
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from prepare_live_visual_refresh import prepare,patch_js,VisualPatchError,MARKER

BACKEND=b"def netstate():\n    return {}\n"
APP=b"""(()=>{'use strict';
let live={},updateInfo={};
function updates(){return 'OLD-UPDATES';}

function render(){if(!live)return;const page={ips,nat,firewall,topology,machines,settings}[screen];return page;}
})();
"""
STYLE=b"body{background:#101010}\n"


class VisualPatchTests(unittest.TestCase):
    def fixture(self,folder):
        folder=Path(folder)
        src=folder/"original"
        (src/"backend").mkdir(parents=True)
        (src/"web").mkdir()
        (src/"backend/server.py").write_bytes(BACKEND)
        (src/"web/app.js").write_bytes(APP)
        (src/"web/style.css").write_bytes(STYLE)
        baseline=folder/"baseline.json"
        baseline.write_text(json.dumps({
            "format":"cerato-live-auth-baseline-v1",
            "server_sha256":hashlib.sha256(BACKEND).hexdigest(),
            "frontend_sha256":hashlib.sha256(APP).hexdigest(),
        }),encoding="utf8")
        return src,baseline

    def test_prepares_only_three_files_preserving_network_backend(self):
        with tempfile.TemporaryDirectory() as folder:
            src,baseline=self.fixture(folder)
            out=Path(folder)/"staging"
            result=prepare(src,out,baseline)
            self.assertTrue(result["source_hashes_verified"])
            self.assertFalse(result["network_modified"])
            self.assertFalse(result["production_modified"])
            self.assertEqual(result["prepared_files"],["backend/server.py","web/app.js","web/style.css"])
            self.assertEqual((out/"backend/server.py").read_bytes(),BACKEND)
            self.assertEqual((src/"web/app.js").read_bytes(),APP)
            self.assertIn("function updates(){",(out/"web/app.js").read_text())
            self.assertNotIn("OLD-UPDATES",(out/"web/app.js").read_text())
            for original in ("ips","nat","firewall","topology","machines","settings"):
                self.assertIn(original,(out/"web/app.js").read_text())
            self.assertIn(MARKER,(out/"web/style.css").read_text())
            if shutil.which("node"):
                subprocess.run(["node","--check",str(out/"web/app.js")],check=True,timeout=10)

    def test_rejects_source_drift_before_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            src,baseline=self.fixture(folder)
            (src/"web/app.js").write_bytes(APP+b"//surprise\n")
            out=Path(folder)/"staging"
            with self.assertRaises(VisualPatchError):
                prepare(src,out,baseline)
            self.assertFalse(out.exists())

    def test_rejects_duplicate_theme_and_unrecognized_update_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            src,baseline=self.fixture(folder)
            (src/"web/style.css").write_text(MARKER,encoding="utf8")
            # Change baseline only for the CSS case, which is not part of source hashes.
            with self.assertRaises(VisualPatchError):
                prepare(src,Path(folder)/"staging",baseline)
            self.assertFalse((Path(folder)/"staging").exists())
        with self.assertRaises(VisualPatchError):
            patch_js("function render(){if(!live)return;}")

if __name__=="__main__":
    unittest.main()

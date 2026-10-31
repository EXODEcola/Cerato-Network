"""Exercise visual-release apply() with a fake panel and deterministic rollback.

No root, WireGuard, network changes or systemctl calls are performed.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
sys.path.insert(0,str(ROOT/"tools"))
import live_controller as ctl

VISUAL={"web/app.js":b"console.log('patched');\n",
        "web/style.css":b"body{background:#1b1f23}\n"}


class VisualInstallIntegrationTests(unittest.TestCase):
    def fixture(self,root:Path):
        files={}
        for rel,data in (("backend/server.py",b"def original_network_backend(): pass\n"),
                         ("web/app.js",b"console.log('old');\n"),
                         ("web/style.css",b"body{background:#000}\n")):
            name=root/"live"/rel
            name.parent.mkdir(parents=True,exist_ok=True)
            name.write_bytes(data)
            files[rel]=name
        saved=root/"backup"
        for rel,name in files.items():
            backup=saved/rel
            backup.parent.mkdir(parents=True,exist_ok=True)
            backup.write_bytes(name.read_bytes())
        return files,saved

    def run_apply(self,files,saved,*,fail_second_health=False):
        root=saved.parent
        state={"installed_version":"v0.0.0",
               "available_version":"v0.1.0-beta.1",
               "history":[]}
        health=[True]*20
        network=["original"]*20
        if fail_second_health:
            # web preflight passes; final web health fails all 6 attempts.
            health=[True]+[False]*10
        def real_replace(replacement):
            self.assertIn(set(replacement),(set(VISUAL),set(files)))
            for rel,data in replacement.items():
                files[rel].write_bytes(data)
        def state_save(_state):
            pass
        def healthcheck():
            return health.pop(0) if health else False
        def networkcheck():
            return network.pop(0)
        with patch.object(ctl.os,"geteuid",return_value=0), \
             patch.object(ctl,"_settings",return_value=({},Path("approved.pub"))), \
             patch.object(ctl,"_state",return_value=state), \
             patch.object(ctl,"_candidate",return_value=root/"mock-signed-bundle"), \
             patch.object(ctl,"_read_overlay",return_value=VISUAL), \
             patch.object(ctl,"_snapshot",return_value=saved), \
             patch.object(ctl,"_replace",side_effect=real_replace), \
             patch.object(ctl,"_network_fingerprint",side_effect=networkcheck), \
             patch.object(ctl,"_web_ok",side_effect=healthcheck), \
             patch.object(ctl,"_cmd",return_value=""), \
             patch.object(ctl,"_save",side_effect=state_save), \
             patch.object(ctl.time,"sleep",return_value=None), \
             patch.object(ctl.shutil,"which",return_value="/usr/bin/node"):
            if fail_second_health:
                with self.assertRaises(ctl.UpdateError):
                    ctl.apply()
            else:
                result=ctl.apply()
                self.assertEqual(result["installed_version"],"v0.1.0-beta.1")
                self.assertEqual(result["status"],"ready")
        return state

    def test_signed_visual_install_leaves_live_backend_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            files,saved=self.fixture(Path(tmp))
            original_backend=files["backend/server.py"].read_bytes()
            state=self.run_apply(files,saved)
            self.assertEqual(files["backend/server.py"].read_bytes(),original_backend)
            self.assertEqual(files["web/app.js"].read_bytes(),VISUAL["web/app.js"])
            self.assertEqual(files["web/style.css"].read_bytes(),VISUAL["web/style.css"])
            self.assertEqual(state["installed_version"],"v0.1.0-beta.1")
            self.assertEqual(len(state["history"]),1)

    def test_health_failure_restores_every_original_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            files,saved=self.fixture(Path(tmp))
            original={rel:p.read_bytes() for rel,p in files.items()}
            state=self.run_apply(files,saved,fail_second_health=True)
            for rel,p in files.items():
                self.assertEqual(p.read_bytes(),original[rel])
            self.assertEqual(state["installed_version"],"v0.0.0")
            self.assertEqual(state["state"],"failed")


if __name__=="__main__":
    unittest.main()

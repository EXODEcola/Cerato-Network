"""Signed routed-UI approval is metadata-only; incompatible source fails closed."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from compose_routed_patch_release import compose,RoutedReleaseError
from build_release import build,verify
import live_controller as ctl

class RoutedUIApprovalTests(unittest.TestCase):
    def make_signed(self,folder):
        base=Path(folder)
        source=base/"source"
        source.mkdir()
        (source/"LICENSE").write_text("MIT")
        (source/"README.md").write_text("Cerato")
        result=compose(ROOT/"integrations/patch_live_routed_ui.py",
                       ROOT/"network/routed_ui_status.py",
                       source/"live-overlay",["v0.0.0"])
        self.assertFalse(result["backend_in_archive"])
        self.assertFalse(result["network_modified"])
        private=base/"key.pem"
        public=base/"pub.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(private)],capture_output=True,check=True)
        subprocess.run(["openssl","pkey","-in",str(private),"-pubout",
                        "-out",str(public)],capture_output=True,check=True)
        output=base/"release"
        build(source,output,"v0.1.1-beta.1",private)
        verify(output,public)
        return output,source

    def test_signed_release_never_contains_historical_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            output,source=self.make_signed(folder)
            names=set(p.name for p in (source/"live-overlay").iterdir())
            self.assertEqual(names,{"compat.json","routed-ui.json"})
            with zipfile.ZipFile(output/"cerato-network-release.zip") as z:
                members=set(z.namelist())
            self.assertIn("cerato-network/live-overlay/routed-ui.json",members)
            self.assertNotIn("cerato-network/live-overlay/backend/server.py",members)
            self.assertNotIn("cerato-network/live-overlay/web/app.js",members)

    def test_refuses_live_source_drift_before_any_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            output,_=self.make_signed(folder)
            root=Path(folder)
            original=root/"old.py"
            frontend=root/"old.js"
            original.write_text("print('unexpected server')\n")
            frontend.write_text("console.log('unexpected frontend');\n")
            with patch.dict(ctl.ALLOWED,{"backend/server.py":original,
                                        "web/app.js":frontend}):
                with self.assertRaisesRegex(ctl.UpdateError,"source IPv4/Web"):
                    ctl._read_overlay(output,"v0.0.0",verify_only=True)
            with self.assertRaises(ctl.UpdateError):
                ctl._read_overlay(output,"v0.1.0-beta.1",verify_only=True)

    def test_composer_refuses_no_source_versions(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RoutedReleaseError):
                compose(ROOT/"integrations/patch_live_routed_ui.py",
                        ROOT/"network/routed_ui_status.py",
                        Path(folder)/"overlay",[])

if __name__=="__main__":
    unittest.main()

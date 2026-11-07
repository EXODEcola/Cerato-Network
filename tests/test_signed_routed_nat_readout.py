"""Signed beta adds a read-only /32 route panel beside NAT, never a fake DNAT."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from compose_nat_routed_readout_release import compose,NATReadoutReleaseError
from build_release import build,verify
from channel_index import create_channel
from stage_signed_static_release import validate as validate_static
import live_controller as ctl

OLD_WEB="""(()=>{
'use strict';
let ceratoIPv4Allocations=null;
async function ceratoLoadIPv4Allocations(){}
function ceratoEnhanceIPv4(){
  const base=document.querySelector('main');
  const data=ceratoIPv4Allocations;
  const routed=new Map();
  if(screen==='nat'){
    if(routed.size){
      console.log('routed');
    }
  }
}
})();
"""

class RoutedNatSignedReleaseTests(unittest.TestCase):
    def make_signed(self,folder):
        folder=Path(folder)
        source=folder/"source"
        source.mkdir()
        (source/"LICENSE").write_text("MIT")
        (source/"README.md").write_text("Cerato")
        result=compose(ROOT/"release-assets/routed-nat-panel.js",
                       source/"live-overlay",["v0.1.1-beta.1"])
        self.assertFalse(result["network_modified"])
        self.assertFalse(result["backend_in_archive"])
        key=folder/"key.pem"
        pub=folder/"pub.pem"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",str(key)],
                        check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(key),"-pubout","-out",str(pub)],
                        check=True,capture_output=True)
        package=folder/"release"
        build(source,package,"v0.1.2-beta.1",key)
        verify(package,pub)
        return package,key,pub

    def test_signed_package_has_js_fragment_only(self):
        with tempfile.TemporaryDirectory() as d:
            output,key,pub=self.make_signed(d)
            with zipfile.ZipFile(output/"cerato-network-release.zip") as z:
                found=set(z.namelist())
            self.assertEqual(found,{
                "cerato-network/LICENSE",
                "cerato-network/README.md",
                "cerato-network/live-overlay/compat.json",
                "cerato-network/live-overlay/web/routed-nat-panel.js",
            })
            channels=Path(d)/"channels"
            create_channel(output,"beta",channels,key,pub,validity_seconds=604800)
            version,files=validate_static(output,channels,pub,"beta")
            self.assertEqual(version,"v0.1.2-beta.1")
            self.assertEqual(len(files),5)

    def test_existing_web_is_safely_extended_without_backend_changes(self):
        with tempfile.TemporaryDirectory() as d:
            package,_,_=self.make_signed(d)
            original=Path(d)/"app.js"
            original.write_text(OLD_WEB)
            with patch.dict(ctl.ALLOWED,{"web/app.js":original}):
                self.assertIsNone(ctl._read_overlay(package,
                                  "v0.1.1-beta.1",verify_only=True))
                result=ctl._read_overlay(package,"v0.1.1-beta.1")
            self.assertEqual(set(result),{"web/app.js"})
            new=result["web/app.js"]
            self.assertEqual(original.read_text(),OLD_WEB)
            self.assertIn(b"Routages IPv4 directs",new)
            self.assertIn(b"ceratoRenderDirectRoutedIPv4(base,data);",new)
            self.assertIn(b"cerato-direct-routed-ipv4",new)
            self.assertEqual(new.count(b"ceratoRenderDirectRoutedIPv4(base,data);"),1)
            self.assertNotIn(b"/api/nat/add",new)
            candidate=Path(d)/"candidate.js"
            candidate.write_bytes(new)
            subprocess.run(["node","--check",str(candidate)],
                           check=True,capture_output=True)

    def test_wrong_baseline_and_double_patch_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            package,_,_=self.make_signed(d)
            original=Path(d)/"app.js"
            original.write_text(OLD_WEB)
            with patch.dict(ctl.ALLOWED,{"web/app.js":original}):
                with self.assertRaises(ctl.UpdateError):
                    ctl._read_overlay(package,"v0.1.0-beta.1",verify_only=True)
                changed=OLD_WEB.replace("function ceratoEnhanceIPv4(){",
                                         "function other(){")
                original.write_text(changed)
                with self.assertRaisesRegex(ctl.UpdateError,"non reconnue"):
                    ctl._read_overlay(package,"v0.1.1-beta.1",verify_only=True)
                original.write_text(OLD_WEB+"\n/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */")
                with self.assertRaises(ctl.UpdateError):
                    ctl._read_overlay(package,"v0.1.1-beta.1",verify_only=True)

    def test_composer_refuses_unknown_asset(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/"bad.js"
            f.write_text("window.location='https://other.example';")
            with self.assertRaises(NATReadoutReleaseError):
                compose(f,Path(d)/"overlay",["v0.1.1-beta.1"])

if __name__=="__main__":
    unittest.main()

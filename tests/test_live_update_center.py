"""Signed update center tests against the *existing* Cerato Web architecture.

No real service restarts, network changes or OVH host access.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
sys.path.insert(0,str(ROOT/"updates"))
sys.path.insert(0,str(ROOT/"tools"))
from patch_live_update_center import patch_backend,patch_frontend,UpgradePatchError
import live_controller as ctl
from build_release import build


SERVER_SAMPLE="""import subprocess,json
class UserError(Exception):pass
def netstate():
    return {}
class Handler:
    def do_GET(self):
        try:
            if p=='/api/status': return self.send_json(200,netstate())
        except UserError:
            pass
    def mutate(self):
        if not self.check_session(write=True):return
        try:
            b=self.read_body()
            if p=='/api/peers':
                pass
"""

APP_SAMPLE="""(()=>{'use strict';
let csrf='',screen='overview',live=null,logs=[],busy=false;const app=document.getElementById('app');
const nav=[['overview','Vue d’ensemble','dashboard'],['settings','Configuration','settings']];
function render(){if(!live)return;let page={overview,ips,machines,nat,firewall,topology,logs,settings}[screen];shell((page||overview)());bind()}
function bind(){const r=$('#refresh-btn');if(r)r.onclick=refresh;document.querySelectorAll('[data-screen]').forEach(b=>b.onclick=()=>{screen=b.dataset.screen;render()});}
})();"""


class LiveUpdateCenterTests(unittest.TestCase):
    def test_backend_keeps_existing_handlers_and_csrf(self):
        patched=patch_backend(SERVER_SAMPLE)
        self.assertIn("if p=='/api/peers':",patched)
        self.assertIn("if p=='/api/status':",patched)
        self.assertIn("if p=='/api/updates':",patched)
        self.assertIn("if p=='/api/updates/check':",patched)
        self.assertIn("if p=='/api/updates/install':",patched)
        self.assertIn("if not self.check_session(write=True)",patched)
        self.assertIn("['sudo','-n','/usr/bin/systemctl','start','--no-block'",patched)
        for bad in ("shell=True","/api/nat/remove'","/api/ip/remove'"):
            self.assertNotIn(bad,patched)

    def test_web_center_navigation_and_controls(self):
        ui=patch_frontend(APP_SAMPLE)
        self.assertIn("['updates','Mises à jour'",ui)
        self.assertIn("function updates(){",ui)
        self.assertIn("id=\"updates-install\"",ui)
        self.assertIn("'/api/updates/check'",ui)
        self.assertIn("'/api/updates/install'",ui)
        self.assertIn("'{overview,ips",ui) if False else self.assertIn("settings,updates}[screen]",ui)
        with self.assertRaises(UpgradePatchError):
            patch_frontend(ui)

    def test_bad_layout_refused(self):
        with self.assertRaises(UpgradePatchError):
            patch_backend("def foo(): pass")
        with self.assertRaises(UpgradePatchError):
            patch_frontend("const nav=[]")

    def test_signed_release_requires_legacy_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            src=root/"src";src.mkdir()
            (src/"LICENSE").write_text("MIT",encoding="utf8")
            (src/"README.md").write_text("Cerato",encoding="utf8")
            payload=src/"live-overlay"
            (payload/"backend").mkdir(parents=True)
            (payload/"web").mkdir(parents=True)
            (payload/"backend/server.py").write_text("print('updated')\n",encoding="utf8")
            (payload/"web/app.js").write_text("console.log('updated');\n",encoding="utf8")
            (payload/"web/style.css").write_text("body {color: #eee}\n",encoding="utf8")
            (payload/"compat.json").write_text(json.dumps({
                "schema":ctl.SCHEMA,"target":"cerato-network-web-8787",
                "from_versions":["v0.0.0"]}),encoding="utf8")
            private=root/"private.pem"
            public=root/"public.pem"
            subprocess.run(["openssl","genpkey","-algorithm","ED25519",
                            "-out",str(private)],check=True,capture_output=True)
            private.chmod(0o600)
            subprocess.run(["openssl","pkey","-in",str(private),"-pubout",
                            "-out",str(public)],check=True,capture_output=True)
            package=root/"signed"
            build(src,package,"v0.1.0-beta.1",private)
            self.assertEqual(set(ctl._read_overlay(package,"v0.0.0")),set(ctl.ALLOWED))
            with self.assertRaises(ctl.UpdateError):
                ctl._read_overlay(package,"v0.2.0")
            (payload/"compat.json").unlink()
            other=root/"generic"
            build(src,other,"v0.1.1-beta.1",private)
            with self.assertRaises(ctl.UpdateError):
                ctl._read_overlay(other,"v0.0.0")

    def test_no_distribution_is_not_installable(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with patch.object(ctl,"STORE",root),patch.object(ctl,"STATE",root/"state.json"),\
                 patch.object(ctl,"SETTING",root/"missing.json"):
                self.assertFalse(ctl.status()["installable"])
                self.assertFalse(ctl.status()["configured"])


if __name__=="__main__":
    unittest.main()

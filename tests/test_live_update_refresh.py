"""Regression: stale updater status must refetch without touching RISE-1 backend."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from repair_live_update_refresh import patch,UpdateRefreshError,MARKER
from patch_live_update_center import patch_frontend

APP_FIXTURE="""(()=>{'use strict';
let csrf='',screen='overview',live=null,logs=[],busy=false;
const nav=[['overview','Vue d’ensemble','dashboard'],['settings','Configuration','settings']];
function render(){if(!live)return;let page={overview,ips,machines,nat,firewall,topology,logs,settings}[screen];shell((page||overview)());bind()}
function bind(){document.querySelectorAll('[data-screen]').forEach(b=>b.onclick=()=>{screen=b.dataset.screen;render()});}
})();"""

class UpdateCenterRefreshTests(unittest.TestCase):
    def test_repairs_existing_legacy_frontend_and_keeps_other_screens(self):
        old=patch_frontend(APP_FIXTURE)
        new=patch(old)
        self.assertIn(MARKER,new)
        self.assertIn("event.target.closest('[data-screen=\"updates\"]')",new)
        self.assertIn("if(target)updateInfo=null;",new)
        self.assertIn("setInterval(function(){",new)
        self.assertIn("reason_code:'web_api_unavailable'",new)
        self.assertIn("API mises à jour indisponible",new)
        self.assertEqual(new.count("function updates(){"),1)
        self.assertEqual(new.count("function render(){if(!live)return;"),1)
        self.assertIn("overview,ips,machines,nat,firewall,topology,logs,settings",new)
        self.assertIn("'/api/updates/install'",new)
        with self.assertRaisesRegex(UpdateRefreshError,"déjà installé"):
            patch(new)
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"app.js"
            file.write_text(new)
            output=subprocess.run(["node","--check",str(file)],capture_output=True,text=True,timeout=10)
            self.assertEqual(output.returncode,0,output.stderr)

    def test_fails_closed_on_unknown_or_partly_modified_frontend(self):
        old=patch_frontend(APP_FIXTURE)
        with self.assertRaises(UpdateRefreshError):
            patch(old.replace("updateInfo=await req('/api/updates');","updateInfo={};"))
        with self.assertRaises(UpdateRefreshError):
            patch(old.replace("function updates(){","function updates2(){"))

    def test_shell_changes_only_frontend_and_has_rollback(self):
        sh=(ROOT/"scripts/repair-live-update-refresh.sh").read_text()
        self.assertIn('cp -p -- "$TARGET" "$BACKUP"',sh)
        self.assertIn('node --check "$SCRATCH/app.js"',sh)
        self.assertIn('[[ "$(network_hash)" == "$BEFORE" ]]',sh)
        for banned in ("wg set","iptables ","nft ","systemctl restart cerato-network-update.service",
                       "auth_basic off","/opt/cerato-network/backend/server.py","scp ","ssh "):
            self.assertNotIn(banned,sh)
        output=subprocess.run(["bash","-n",str(ROOT/"scripts/repair-live-update-refresh.sh")],
                              capture_output=True,text=True)
        self.assertEqual(output.returncode,0,output.stderr)

if __name__=="__main__":
    unittest.main()

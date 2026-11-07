"""Validate actual inactive RISE-1 staging using synthetic, private source only.

Never execute the historical backend; never read an active auth database.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import verify_private_native_auth_stage as check
from stage_current_live_auth_candidate import stage_candidate

SECRET="PRIVATE_BACKEND_VALUE_DO_NOT_PRINT"
BACKEND=f"""PRIVATE_TOKEN='{SECRET}'
def netstate(): return {{'tunnel_active':True}}
def cerato_reject_routed_nat(addr): return None
class Handler:
    def check_session(self,write=False): return False
    def send_json(self,status,body): return (status,body)
    def read_body(self): return {{}}
    def do_GET(self):
        if self.path=='/api/status': return self.send_json(200,{{}})
        if self.path=='/api/ip/allocations': return self.send_json(200,{{}})
        if self.path=='/api/login': return self.send_json(410,{{}})
        if self.path=='/api/logout': return self.send_json(410,{{}})
    def do_POST(self):
        if self.path=='/api/nat/add':
            cerato_reject_routed_nat('198.51.100.1')
            return self.send_json(200,{{}})
"""
APP="""const screens=['overview','ips','machines','nat','firewall','topology','logs','settings','updates'];
let live={};let screen='overview';
function render(){if(!live)return;}
function bind(){}
function updates(){}
async function ceratoLoadIPv4Allocations(){}
function ceratoEnhanceIPv4(){}
function ceratoRenderDirectRoutedIPv4(base,data){}
/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */
"""
CSS="/* CERATO NETWORK — Graphite Operations */\nbody{background:#101215;}"

class VerifyNativeCandidateTests(unittest.TestCase):
    def fixture(self,parent):
        root=Path(parent)
        live=root/"live"
        backups=root/"backups"
        backups.mkdir(mode=0o700)
        backups.chmod(0o700)
        (live/"backend").mkdir(parents=True)
        (live/"web").mkdir()
        files={
            "server_sha256":live/"backend/server.py",
            "frontend_sha256":live/"web/app.js",
            "style_sha256":live/"web/style.css",
        }
        files["server_sha256"].write_text(BACKEND)
        files["frontend_sha256"].write_text(APP)
        files["style_sha256"].write_text(CSS)
        pinned={k:hashlib.sha256(p.read_bytes()).hexdigest()
                for k,p in files.items()}
        stage=stage_candidate(live,backups=backups,expected_hashes={
            "backend":pinned["server_sha256"],
            "frontend":pinned["frontend_sha256"],
            "css":pinned["style_sha256"],
        })
        return live,backups,Path(stage["private_directory"]),pinned

    def test_full_candidate_immutable_and_explicitly_not_production_ready(self):
        with tempfile.TemporaryDirectory() as d:
            live,backups,candidate,pinned=self.fixture(d)
            source_before={f.relative_to(live).as_posix():f.read_bytes()
                           for f in live.rglob("*") if f.is_file()}
            with patch.object(check,"BACKUPS",backups), \
                 patch.object(check,"service_context",return_value={
                     "inspected":True,"user_is_ceratonet":True,
                     "private_auth_storage_writable":False,
                     "https_origin_declared":False,
                 }), \
                 patch.object(check,"storage_state",return_value={
                     "directory_ready":False,"new_account_created":False,
                     "database_read":False,
                 }):
                output=check.inspect(root=backups,live=live,repo=ROOT,
                      pinned=pinned,owner=os.geteuid())
            source_after={f.relative_to(live).as_posix():f.read_bytes()
                          for f in live.rglob("*") if f.is_file()}
            self.assertEqual(source_before,source_after)
            self.assertEqual(output["candidate_count_verified"],1)
            self.assertTrue(output["candidate_integrity_verified"])
            self.assertTrue(output["security_modules_match_trusted_source"])
            self.assertTrue(output["private_backend_compiled"])
            self.assertTrue(output["private_frontend_js_checked"])
            self.assertFalse(output["safe_to_cut_over"])
            self.assertFalse(output["prerequisites_satisfied"])
            self.assertFalse(output["network_modified"])
            self.assertFalse(output["production_modified"])
            self.assertFalse(output["web_restarted"])
            self.assertFalse(output["private_source_exported"])
            self.assertNotIn(SECRET,json.dumps(output))
            self.assertNotIn("198.51.100.1",json.dumps(output))
            self.assertFalse(list(backups.rglob("accounts.sqlite3")))

    def test_modified_live_source_invalidates_staged_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            live,backups,candidate,pinned=self.fixture(d)
            (live/"web/app.js").write_text(APP+"\n//source modified")
            with patch.object(check,"BACKUPS",backups), \
                 self.assertRaisesRegex(check.VerificationError,"Aucune copie"):
                check.inspect(root=backups,live=live,repo=ROOT,
                              pinned=pinned,owner=os.geteuid())

    def test_modified_private_security_module_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            live,backups,candidate,pinned=self.fixture(d)
            (candidate/"server/security/live_http_bridge.py").write_text("# altered")
            with patch.object(check,"BACKUPS",backups), \
                 self.assertRaisesRegex(check.VerificationError,"Aucune copie"):
                check.inspect(root=backups,live=live,repo=ROOT,
                              pinned=pinned,owner=os.geteuid())

    def test_symbolic_private_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            live,backups,candidate,pinned=self.fixture(d)
            decoy=backups/"cerato-private-auth-candidate.symbolic"
            decoy.symlink_to(candidate,target_is_directory=True)
            with patch.object(check,"BACKUPS",backups):
                with self.assertRaises(check.VerificationError):
                    check.check_one(decoy,live=live,repo=ROOT,
                                    pinned=pinned,owner=os.geteuid())

    def test_candidate_modules_compile_but_are_never_imported(self):
        with tempfile.TemporaryDirectory() as d:
            live,backups,candidate,pinned=self.fixture(d)
            attack=(candidate/"server/security/auth_store.py")
            attack.write_text("raise RuntimeError('executed a private module')")
            with patch.object(check,"BACKUPS",backups), \
                 self.assertRaises(check.VerificationError):
                check.check_one(candidate,live=live,repo=ROOT,
                                pinned=pinned,owner=os.geteuid())

if __name__=="__main__":
    unittest.main()

"""Staging the current private 8787 backend must never touch the live source."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from stage_current_live_auth_candidate import stage_candidate,PrivateStageError

SECRET="R5_PRIVATE_EXAMPLE_DO_NOT_LOG"
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
function render(){if(!live)return;}
function bind(){}
function updates(){}
async function ceratoLoadIPv4Allocations(){}
function ceratoEnhanceIPv4(){}
function ceratoRenderDirectRoutedIPv4(base,data){}
/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */
"""
CSS="/* CERATO NETWORK — Graphite Operations */\nbody{background:#101215;}"

class PrivateCurrentStageTests(unittest.TestCase):
    def fixture(self,root):
        live=root/"live"
        (live/"backend").mkdir(parents=True)
        (live/"web").mkdir()
        (live/"backend/server.py").write_text(BACKEND)
        (live/"web/app.js").write_text(APP)
        (live/"web/style.css").write_text(CSS)
        backups=root/"backups"
        backups.mkdir(mode=0o700)
        return live,backups

    def test_private_candidate_compiles_preserves_live_and_never_claims_cutover(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            live,backups=self.fixture(root)
            before={p.relative_to(live):p.read_bytes()
                    for p in live.rglob("*") if p.is_file()}
            result=stage_candidate(live,backups=backups)
            private=Path(result["private_directory"])
            self.assertTrue(private.is_dir())
            self.assertEqual(private.stat().st_mode&0o777,0o700)
            self.assertEqual((private/"server/backend/server.py").stat().st_mode&0o777,0o600)
            self.assertEqual((private/"client/web/app.js").stat().st_mode&0o777,0o600)
            self.assertIn("CERATO_AUTH_BRIDGE_STAGED",
                          (private/"server/backend/server.py").read_text())
            self.assertIn("CERATO_AUTH_OVERLAY_STAGING",
                          (private/"client/web/app.js").read_text())
            self.assertIn("CERATO-NETWORK-ROUTED-NAT-UI-V1",
                          (private/"client/web/app.js").read_text())
            self.assertTrue(result["contains_private_source"])
            self.assertTrue(result["frontend_syntax_validated"])
            self.assertFalse(result["production_cutover_approved"])
            self.assertFalse(result["safe_to_disable_legacy_login"])
            self.assertFalse(result["production_modified"])
            self.assertFalse(result["nginx_modified"])
            self.assertFalse(result["network_modified"])
            self.assertFalse(result["service_restarted"])
            packed=json.dumps(result)
            self.assertNotIn(SECRET,packed)
            after={p.relative_to(live):p.read_bytes()
                   for p in live.rglob("*") if p.is_file()}
            self.assertEqual(before,after)
            # The candidate remains PRIVATE, never a distributable build.
            self.assertNotIn(SECRET,(private/"manifest.json").read_text())

    def test_explicit_fingerprints_match_approved_audit_only(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            live,backups=self.fixture(root)
            sha={
                "backend":hashlib.sha256((live/"backend/server.py").read_bytes()).hexdigest(),
                "frontend":hashlib.sha256((live/"web/app.js").read_bytes()).hexdigest(),
                "css":hashlib.sha256((live/"web/style.css").read_bytes()).hexdigest(),
            }
            incorrect={**sha,"backend":"f"*64}
            with self.assertRaisesRegex(PrivateStageError,"différentes"):
                stage_candidate(live,backups=backups,expected_hashes=incorrect)
            self.assertEqual(list(backups.iterdir()),[])
            result=stage_candidate(live,backups=backups,expected_hashes=sha)
            self.assertEqual(result["result"],"staged_inactive")
            self.assertFalse(result["production_modified"])
            self.assertTrue(Path(result["private_directory"]).is_dir())

    def test_unknown_api_route_refuses_staging_without_creating_files(self):
        with tempfile.TemporaryDirectory() as t:
            live,backups=self.fixture(Path(t))
            backend=live/"backend/server.py"
            backend.write_text(BACKEND+"\nSECRET_ROUTE='/api/not-approved'\n")
            with self.assertRaises(PrivateStageError):
                stage_candidate(live,backups=backups)
            self.assertEqual(list(backups.iterdir()),[])

    def test_missing_latest_signed_ui_marker_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            live,backups=self.fixture(Path(t))
            app=live/"web/app.js"
            app.write_text(APP.replace("CERATO-NETWORK-ROUTED-NAT-UI-V1","OLD"))
            with self.assertRaises(PrivateStageError):
                stage_candidate(live,backups=backups)
            self.assertEqual(list(backups.iterdir()),[])

    def test_untrusted_backup_dir_rejected_before_any_file_write(self):
        with tempfile.TemporaryDirectory() as t:
            live,backups=self.fixture(Path(t))
            backups.chmod(0o777)
            with self.assertRaises(PrivateStageError):
                stage_candidate(live,backups=backups)
            self.assertEqual(list(backups.iterdir()),[])

if __name__=="__main__":
    unittest.main()

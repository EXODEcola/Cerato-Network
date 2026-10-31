"""End-to-end *static* private candidate rehearsal, no sockets or active server."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from rehearse_native_auth import rehearse, RehearsalError
from check_live_auth_cutover import EXPECTED_ROUTES, REQUIRED_HOOKS, REQUIRED_SECTIONS

SOURCE=b"""# private backend, never publish to GitHub
PASSWORD_VALUE='NOT-FOR-RELEASE'
def netstate():return {}
class Handler(object):
    def check_session(self,write=False):return True
    def send_json(self,code,body):return (code,body)
    def do_GET(self):return self.send_json(200,netstate())
    def do_POST(self):return self.send_json(200,{'ok':True})
"""
APP=b"""let live={};
async function req(path){return fetch(path,{method:'GET',credentials:'same-origin'});}
function overview(){return req('/api/status');}
function updates(){return 'Release update';}
function bind(){return true;}
function dashboard(){return 'Dashboard';}
function ips(){return 'IPv4';}
function machines(){return 'Dell';}
function nat(){return 'NAT';}
function firewall(){return 'Firewall';}
function topology(){return 'Topology';}
function render(){if(!live)return;return overview();}
"""
CSS="/* CERATO NETWORK — Graphite Operations */\nbody{background:#111;}".encode()

class PrivateRehearsalTests(unittest.TestCase):
    def make_source(self,root):
        src=root/"live"
        (src/"backend").mkdir(parents=True)
        (src/"web").mkdir()
        for name,data in {"backend/server.py":SOURCE,
                          "web/app.js":APP,"web/style.css":CSS}.items():
            (src/name).write_bytes(data)
        hashes={
            "format":"cerato-live-auth-baseline-v1",
            "server_sha256":hashlib.sha256(SOURCE).hexdigest(),
            "frontend_sha256":hashlib.sha256(APP).hexdigest()
        }
        base=root/"baseline.json"
        base.write_text(json.dumps(hashes))
        inv={
            "format":"cerato-live-auth-compat-v1",
            "api_routes":sorted(EXPECTED_ROUTES),
            "auth_hooks":sorted(REQUIRED_HOOKS),
            "ui_sections":sorted(REQUIRED_SECTIONS),
            "compatible_for_adapter_design":True,
            "direct_network_mutations":False,
            "server_bytes":len(SOURCE),"frontend_bytes":len(APP),
            **{"server_sha256":hashes["server_sha256"],
               "frontend_sha256":hashes["frontend_sha256"]}
        }
        handler={"candidate_count":1,"unclassified_count":0}
        return src,base,inv,handler

    def test_private_clone_compiles_and_cleans_without_changing_live(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            src,base,inv,http=self.make_source(root)
            before={p.name:p.read_bytes() for p in src.rglob("*") if p.is_file()}
            with patch("rehearse_native_auth.inspect_source",return_value=inv),\
                 patch("rehearse_native_auth.inspect_handlers",return_value=http),\
                 patch("rehearse_native_auth.tempfile.TemporaryDirectory",
                       wraps=tempfile.TemporaryDirectory) as tmp:
                report=rehearse(src,baseline=base,inspect_source=lambda *_:inv,
                               inspect_handlers=lambda *_:http)
            self.assertTrue(report["candidate_compiled"])
            self.assertTrue(report["private_stage_deleted"])
            self.assertFalse(report["production_modified"])
            self.assertFalse(report["production_cutover_ready"])
            self.assertFalse(report["private_source_exported"])
            self.assertEqual(before,{p.name:p.read_bytes() for p in src.rglob("*") if p.is_file()})
            self.assertNotIn("NOT-FOR-RELEASE",json.dumps(report))

    def test_drift_refused_before_private_source_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            src,base,inv,http=self.make_source(Path(directory))
            inv=dict(inv,server_sha256="0"*64)
            with patch("rehearse_native_auth.backend_prepare",side_effect=AssertionError("must not prepare")):
                result=rehearse(src,baseline=base,
                               inspect_source=lambda *_:inv,
                               inspect_handlers=lambda *_:http)
            self.assertFalse(result["verified_exact_source"])
            self.assertFalse(result["candidate_compiled"])
            self.assertFalse(result["production_cutover_ready"])
            self.assertFalse(result["baseline_backend_matches"])

    def test_symlink_and_missing_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            src,base,inv,http=self.make_source(Path(directory))
            (src/"web/app.js").unlink()
            (src/"web/app.js").symlink_to(src/"backend/server.py")
            with self.assertRaises(RehearsalError):
                rehearse(src,baseline=base,
                         inspect_source=lambda *_:inv,
                         inspect_handlers=lambda *_:http)

    def test_no_live_restart_or_network_invocation(self):
        source=(ROOT/"integrations/rehearse_native_auth.py").read_text()
        for invalid in ("systemctl restart","subprocess.Popen","socket.socket",
                        "AuthStore(","sudo ","wget ","curl ","git push",
                        "nft ","iptables ","wg set","connect("):
            self.assertNotIn(invalid,source)
        self.assertIn("TemporaryDirectory",source)
        self.assertIn("source_baseline_or_route_audit_requires_review",source)

if __name__=="__main__":
    unittest.main()

"""Native login overlay staging keeps the existing router UI intact."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from stage_live_auth_frontend import stage,NativeAuthUIStageError,MARKER

BACKEND=b"""def netstate(): return {}
class Handler:
    def check_session(self): return True
    def send_json(self,*a): return None
    def read_body(self): return {}
    def do_GET(self): return None
    def do_POST(self): return None
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
CSS=b"/* CERATO NETWORK \xe2\x80\x94 Graphite Operations */\nbody{background:#111;}"


class StageNativeLoginTests(unittest.TestCase):
    def fixture(self,root):
        root=Path(root)
        source=root/"live"
        (source/"backend").mkdir(parents=True)
        (source/"web").mkdir()
        (source/"backend/server.py").write_bytes(BACKEND)
        (source/"web/app.js").write_bytes(APP)
        (source/"web/style.css").write_bytes(CSS)
        baseline=root/"baseline.json"
        baseline.write_text(json.dumps({
            "format":"cerato-live-auth-baseline-v1",
            "server_sha256":hashlib.sha256(BACKEND).hexdigest(),
            "frontend_sha256":hashlib.sha256(APP).hexdigest(),
        }),encoding="utf8")
        return source,baseline

    def test_native_login_stages_only_web_files(self):
        with tempfile.TemporaryDirectory() as root:
            source,baseline=self.fixture(root)
            before={p:(source/"web"/p).read_bytes() for p in ("app.js","style.css")}
            output=Path(root)/"private-stage"
            response=stage(source,output,baseline=baseline)
            self.assertFalse(response["ready_for_production"])
            self.assertFalse(response["production_modified"])
            self.assertFalse(response["nginx_modified"])
            self.assertFalse(response["network_modified"])
            self.assertEqual(response["staged_files"],["web/app.js","web/style.css"])
            js=(output/"web/app.js").read_text(encoding="utf8")
            css=(output/"web/style.css").read_text(encoding="utf8")
            self.assertIn(MARKER,js)
            self.assertIn("function overview(){",js)
            self.assertIn("function nat(){",js)
            self.assertIn("window.fetch=legacyFetch;",js)
            self.assertIn("headers.set('X-Cerato-CSRF',state.csrf)",js)
            self.assertIn("endpoint+'mfa/verify'",js)
            self.assertIn("cerato-auth-dialog",css)
            self.assertEqual(output.stat().st_mode & 0o777,0o700)
            self.assertEqual((output/"web/app.js").stat().st_mode & 0o777,0o600)
            self.assertEqual({p:(source/"web"/p).read_bytes() for p in before},before)

    def test_wrong_backend_or_old_interface_is_rejected_without_staging(self):
        with tempfile.TemporaryDirectory() as root:
            source,baseline=self.fixture(root)
            out=Path(root)/"private-stage"
            with (source/"backend/server.py").open("ab") as f:f.write(b"# drift")
            with self.assertRaises(NativeAuthUIStageError):
                stage(source,out,baseline=baseline)
            self.assertFalse(out.exists())
            (source/"backend/server.py").write_bytes(BACKEND)
            (source/"web/app.js").write_bytes(b"console.log('unknown UI')")
            with self.assertRaises(NativeAuthUIStageError):
                stage(source,out,baseline=baseline)
            self.assertFalse(out.exists())

    def test_frontend_hash_drift_blocks_before_any_file_is_written(self):
        with tempfile.TemporaryDirectory() as root:
            source,baseline=self.fixture(root)
            app=source/"web/app.js"
            app.write_bytes(app.read_bytes()+b"\n// changed without approval")
            destination=Path(root)/"auth-stage"
            with self.assertRaisesRegex(NativeAuthUIStageError,"frontend non approuvée"):
                stage(source,destination,baseline=baseline)
            self.assertFalse(destination.exists())

    def test_css_marker_and_existing_overlay_required(self):
        with tempfile.TemporaryDirectory() as root:
            source,baseline=self.fixture(root)
            (source/"web/style.css").write_text("body{}")
            with self.assertRaises(NativeAuthUIStageError):
                stage(source,Path(root)/"result",baseline=baseline)
            (source/"web/style.css").write_bytes(CSS)
            (source/"web/app.js").write_bytes(APP+MARKER.encode())
            with self.assertRaises(NativeAuthUIStageError):
                stage(source,Path(root)/"result",baseline=baseline)

    def test_unverified_legacy_api_transport_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            source,baseline=self.fixture(root)
            old=(source/"web/app.js").read_bytes()
            modified=old.replace(b"fetch(path",b"fetch2(path")
            (source/"web/app.js").write_bytes(modified)
            import hashlib,json
            base=json.loads(baseline.read_text())
            base["frontend_sha256"]=hashlib.sha256(modified).hexdigest()
            baseline.write_text(json.dumps(base))
            with self.assertRaisesRegex(NativeAuthUIStageError,"Transport API"):
                stage(source,Path(root)/"output",baseline=baseline)

    def test_native_login_does_not_store_sessions_in_local_storage(self):
        source=(ROOT/"web/live-auth-overlay.js").read_text(encoding="utf8")
        for required in ("/api/auth/","/api/accounts","credentials:'same-origin'",
                         "csrf","challenge","recovery_codes","location.reload()"):
            self.assertIn(required,source)
        for prohibited in ("localStorage","sessionStorage","eval(","new Function("):
            self.assertNotIn(prohibited,source)

if __name__=="__main__":
    unittest.main()

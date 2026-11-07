"""Cutover audit never emits private source or declares the live migration safe."""
from __future__ import annotations
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import audit_live_8787_auth_cutover as check

PRIVATE="VERY-PRIVATE-SECRET-EXAMPLE-DO-NOT-SHARE"
BACKEND=f'''# do not print this private source
PRIVATE_PASSWORD = "{PRIVATE}"
def netstate(): return {{"tunnel_active":True}}
class Handler:
    def check_session(self,write=False): return False
    def send_json(self,code,obj): return (code,obj)
    def read_body(self): return {{}}
    def do_GET(self):
        if self.path=="/api/status": return self.send_json(200,{{}})
        if self.path=="/api/ip/allocations": return self.send_json(200,{{}})
        if self.path=="/api/login": return self.send_json(410,{{}})
        if self.path=="/api/logout": return self.send_json(410,{{}})
    def do_POST(self):
        if self.path=="/api/nat/add":
            cerato_reject_routed_nat("192.0.2.1")
            return self.send_json(200,{{}})
'''
FRONTEND="""
let screen='overview';
function render(){if(!live)return;}
function bind(){}
function updates(){}
async function ceratoLoadIPv4Allocations(){}
function ceratoEnhanceIPv4(){}
function ceratoRenderDirectRoutedIPv4(base,data){}
const views=['overview','ips','machines','nat','firewall','topology','logs','settings','updates'];
/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */
"""
STYLE="/* CERATO NETWORK — Graphite Operations */ body { background: #101215; }"

class LiveAuditTests(unittest.TestCase):
    def test_safe_source_redaction_and_post_beta_contract(self):
        value=check.analyze(BACKEND.encode(),FRONTEND.encode(),STYLE.encode())
        self.assertTrue(value["http_handler_single_and_unmodified"])
        self.assertTrue(value["netstate_function_present"])
        self.assertTrue(value["routed_ipv4_api_present"])
        self.assertTrue(value["routed_nat_guard_present"])
        self.assertTrue(value["signed_nat_readout_present"])
        self.assertTrue(all(value["frontend"].values()))
        self.assertTrue(all(value["frontend_sections"].values()))
        self.assertEqual(value["unknown_api_route_count"],0)
        self.assertNotIn(PRIVATE,json.dumps(value))
        self.assertNotIn("192.0.2.1",json.dumps(value))
        self.assertEqual(value["installed_backend_sha256"],
                         hashlib.sha256(BACKEND.encode()).hexdigest())

    def test_unknown_route_is_counted_without_leaking_name(self):
        extra=BACKEND.replace('def do_POST(self):',
            'def do_POST(self):\n        if self.path=="/api/private/secret": return self.send_json(200,{})')
        report=check.analyze(extra.encode(),FRONTEND.encode(),STYLE.encode())
        self.assertEqual(report["unknown_api_route_count"],1)
        self.assertNotIn("/api/private/secret",json.dumps(report))

    def test_duplicate_or_decorated_handler_makes_staging_ineligible(self):
        duplicate=BACKEND+"\n"+BACKEND[BACKEND.index("class Handler:"):].replace(
            "class Handler:","class AnotherHandler:")
        d=check.analyze(duplicate.encode(),FRONTEND.encode(),STYLE.encode())
        self.assertFalse(d["http_handler_single_and_unmodified"])
        decorated=BACKEND.replace("class Handler:","@decorator\nclass Handler:")
        d=check.analyze(decorated.encode(),FRONTEND.encode(),STYLE.encode())
        self.assertFalse(d["http_handler_single_and_unmodified"])

    def test_missing_required_screen_blocks_eligibility(self):
        with tempfile.TemporaryDirectory() as t:
            base=Path(t)
            (base/"backend").mkdir()
            (base/"web").mkdir()
            (base/"backend/server.py").write_text(BACKEND)
            (base/"web/app.js").write_text(FRONTEND)
            (base/"web/style.css").write_text(STYLE)
            baseline={
                "inspection":"structural",
                "web_user_expected":True,
                "protect_system_strict":True,
                "auth_storage_write_scope":False,
            }
            before={x.relative_to(base):x.read_bytes()
                    for x in base.rglob("*") if x.is_file()}
            out=check.report(base,systemd=lambda:baseline,
                             proxy=lambda:{"inspection":"unavailable"},
                             account=lambda:{"trusted_directory":False})
            after={x.relative_to(base):x.read_bytes()
                   for x in base.rglob("*") if x.is_file()}
            self.assertEqual(before,after)
            self.assertTrue(out["candidate_staging_eligible"])
            for key in ("safe_to_cut_over","safe_to_disable_legacy_login",
                        "safe_to_modify_nginx","production_modified",
                        "network_modified","private_source_exported",
                        "private_account_records_exported"):
                self.assertFalse(out[key])
            self.assertNotIn(PRIVATE,json.dumps(out))
            (base/"web/app.js").write_text(FRONTEND.replace("'settings'","'other'"))
            bad=check.report(base,systemd=lambda:baseline,
                             proxy=lambda:{},account=lambda:{})
            self.assertFalse(bad["candidate_staging_eligible"])

    def test_dangerous_missing_and_symlink_sources_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            real=Path(tmp)/"live"
            real.write_text(BACKEND)
            link=Path(tmp)/"symbolic"
            link.symlink_to(real)
            with self.assertRaises(check.CutoverAuditError):
                check.source(link)
            with self.assertRaises(check.CutoverAuditError):
                check.source(Path(tmp)/"missing")

    def test_proxy_output_redacts_every_directive(self):
        conf=("auth_basic \"CERATO-SECRET\";\n"
              "auth_basic_user_file /etc/nginx/VERY-PRIVATE-PASSWD;\n")
        proc=SimpleNamespace(returncode=0,stdout=conf)
        with patch.object(check,"run_readonly",return_value=proc):
            state=check.proxy_status()
        self.assertTrue(state["basic_auth_present_somewhere"])
        self.assertNotIn("VERY-PRIVATE",json.dumps(state))
        self.assertFalse(state["native_auth_http_cutover_verified"])

    def test_unit_reports_boolean_only(self):
        props=("User=ceratonet\nProtectSystem=strict\n"
            "ProtectHome=yes\nPrivateTmp=yes\nNoNewPrivileges=yes\n"
            "ReadWritePaths=/var/lib/cerato-network-auth\n"
            "Environment=TOP_SECRET=1234\n")
        def fake(*args,**kwargs):
            if "show" in args:
                return SimpleNamespace(returncode=0,stdout=props)
            return SimpleNamespace(returncode=0,stdout="")
        with patch.object(check,"run_readonly",side_effect=fake):
            result=check.systemd_status()
        self.assertTrue(result["web_user_expected"])
        self.assertTrue(result["auth_storage_write_scope"])
        self.assertNotIn("TOP_SECRET",json.dumps(result))

if __name__=="__main__":
    unittest.main()

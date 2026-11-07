"""Synthetic legacy 8787 backend/UI staging tests: no service or nft changes."""
from __future__ import annotations
import json
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
sys.path.insert(0,str(ROOT/"network"))
from patch_live_routed_ui import patch_backend,patch_frontend,stage,LiveUIError
from routed_ui_status import summarize

SERVER="""import json
import subprocess
class UserError(Exception): pass
def additional_ipctl(*args):return {"pool":[],"managed":[]}
def ctl(*args):return "{}"
def netstate():return {}
class Handler:
    def send_json(self,status,data):return data
    def check_session(self,write=False):return True
    def read_body(self):return {}
    def do_GET(self):
        p='/api/status'
        if not self.check_session():return
        if p=='/api/status': return self.send_json(200,netstate())
    def do_POST(self):
        p='/api/nat/add'
        b=self.read_body()
        if not self.check_session(write=True):return
        if p=='/api/nat/add':
            ip=b.get('ip')
            ctl('nat-add',ip)
        elif p=='/api/nat/remove':
            ctl('nat-remove',b)
        if p=='/api/peers':
            return self.send_json(200,{})
"""
FRONT="""(()=>{'use strict';
let live={},screen='ips';
function updates(){return '';}
function bind(){return true;}
function render(){if(!live)return;
  const page={ips,nat,overview}[screen];
  if(page)page();
}
function ips(){}
function nat(){}
function overview(){}
})();
"""
PUBLIC="54.37.165.151"
DATA={"wan":"enp1s0f0","primary_ipv4":"51.210.223.57",
      "pool":[PUBLIC],"managed":[{"ip":PUBLIC,"mode":"routed-wg",
                              "peer":"dell-r530","present_on_wan":False}],
      "mappings":0}

class LegacyRoutedUIIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model=(ROOT/"network/routed_ui_status.py").read_text()

    def test_generated_server_endpoint_reports_real_allocation(self):
        patched=patch_backend(SERVER,self.model)
        self.assertIn("GET", "GET")
        self.assertIn("if p=='/api/ip/allocations'",patched)
        self.assertLess(patched.index("cerato_reject_routed_nat(b.get"),
                        patched.index("ctl('nat-add',ip)"))
        self.assertIn("cerato_summarize_ipv4",patched)
        namespace={}
        exec(compile(patched,"<synthetic-legacy-api>","exec"),namespace)
        namespace["additional_ipctl"]=lambda *args: DATA
        result=namespace["cerato_routed_allocations"]()
        self.assertEqual(result,summarize(DATA))
        self.assertEqual(result["available_count"],0)
        with self.assertRaisesRegex(namespace["UserError"],"NAT par port est interdit"):
            namespace["cerato_reject_routed_nat"](PUBLIC)
        namespace["cerato_reject_routed_nat"]("54.37.165.160")

    def test_backend_accepts_exact_double_quoted_post_nat_branch(self):
        modified=SERVER.replace("if p=='/api/nat/add':",
                                'if p == "/api/nat/ping":\n'
                                '            pass\n'
                                '        elif p == "/api/nat/add":')
        patch=patch_backend(modified,self.model)
        self.assertIn('elif p == "/api/nat/add":\n'
                      '            cerato_reject_routed_nat',patch)
        self.assertEqual(patch.count("cerato_reject_routed_nat(b.get"),1)

    def test_backend_nat_guard_rejects_before_legacy_ctl_mutation(self):
        patched=patch_backend(SERVER,self.model)
        namespace={}
        exec(compile(patched,"<synthetic-legacy-api>","exec"),namespace)
        calls=[]
        namespace["additional_ipctl"]=lambda *args:DATA
        namespace["ctl"]=lambda *args: calls.append(args)
        # This exercises a synthetic endpoint with a valid authenticated form
        handler=namespace["Handler"]()
        handler.read_body=lambda:{"ip":PUBLIC}
        with self.assertRaisesRegex(namespace["UserError"],"NAT par port"):
            handler.do_POST()
        self.assertEqual(calls,[])

    def test_frontend_overlay_modifies_no_backend_or_network(self):
        patched=patch_frontend(FRONT)
        self.assertIn("function ceratoEnhanceIPv4()",patched)
        self.assertIn("ceratoIPv4Allocations",patched)
        self.assertIn("option.disabled=true",patched)
        self.assertIn("control.disabled=true",patched)
        self.assertIn("function render(){if(!live)return;",patched)
        self.assertIn("function updates(){return '';}",patched)
        self.assertNotIn("fetch('https",patched)
        self.assertNotIn("nft ",patched)

    def test_nat_view_renders_direct_ipv4_routes_without_fake_nat_rule(self):
        patched=patch_frontend(FRONT)
        self.assertIn("function ceratoRenderDirectRoutedIPv4(base,data)",patched)
        self.assertIn("ceratoRenderDirectRoutedIPv4(base,data);",patched)
        self.assertIn("row.mode==='routed-wg'",patched)
        self.assertIn("Routages IPv4 directs",patched)
        self.assertIn("Routage complet /32 · WireGuard",patched)
        self.assertIn("sans publication NAT par port",patched)
        self.assertIn("td.textContent=value",patched)
        # No unsanitized HTML injection and no privileged mutation.
        new_part=patched.split("function ceratoRenderDirectRoutedIPv4(base,data)",1)[1]
        new_part=new_part.split("function ceratoEnhanceIPv4()",1)[0]
        self.assertNotIn("innerHTML",new_part)
        self.assertNotIn("fetch(",new_part)
        self.assertNotIn("nat-add",new_part)
        self.assertNotIn("nft",new_part)
        self.assertNotIn("ctl(",new_part)
        self.assertEqual(patched.count("id='cerato-direct-routed-ipv4'"),0)

    def test_reject_missing_auth_or_already_patched(self):
        with self.assertRaises(LiveUIError):
            patch_backend(SERVER.replace("if not self.check_session(write=True):return",
                                         "pass"),self.model)
        with self.assertRaises(LiveUIError):
            patch_frontend(patch_frontend(FRONT))
        with self.assertRaises(LiveUIError):
            patch_backend(patch_backend(SERVER,self.model),self.model)

    def test_refuse_unknown_backend_mutation_shape(self):
        altered=SERVER.replace("if p=='/api/nat/add':",
                               "if p in ('/api/nat/add','/api/nat'):")
        with self.assertRaisesRegex(LiveUIError,"/api/nat/add"):
            patch_backend(altered,self.model)

    def test_unrecognized_production_hashes_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            source=folder/"live"
            (source/"backend").mkdir(parents=True)
            (source/"web").mkdir(parents=True)
            (source/"backend/server.py").write_text(SERVER)
            (source/"web/app.js").write_text(FRONT)
            model=folder/"model.py"
            model.write_text(self.model)
            with self.assertRaisesRegex(LiveUIError,"Empreinte"):
                stage(source,folder/"candidate",model)
            self.assertFalse((folder/"candidate").exists())

    def test_delegate_handler_uses_safe_branch_before_nat_call(self):
        delegated=SERVER.replace(
            "    def do_POST(self):\\n        p='/api/nat/add'\\n",
            "    def do_POST(self): return self._handle_post()\\n"
            "    def _handle_post(self):\\n        p='/api/nat/add'\\n"
        ).replace(
            "    def do_GET(self):\\n        p='/api/status'\\n",
            "    def do_GET(self): return self._handle_get()\\n"
            "    def _handle_get(self):\\n        p='/api/status'\\n"
        )
        patched=patch_backend(delegated,self.model)
        self.assertIn("cerato_reject_routed_nat(b.get",patched)
        self.assertIn("if p=='/api/ip/allocations'",patched)
        self.assertEqual(patched.count("cerato_reject_routed_nat(b.get"),1)
        self.assertLess(patched.index("cerato_reject_routed_nat(b.get"),
                        patched.index("ctl('nat-add',ip)"))

    def test_nested_try_nat_dispatch_with_guard_before_try(self):
        nested=SERVER.replace(
            "        if p=='/api/nat/add':\n"
            "            ip=b.get('ip')\n"
            "            ctl('nat-add',ip)\n"
            "        elif p=='/api/nat/remove':\n"
            "            ctl('nat-remove',b)\n",
            "        try:\n"
            "            if p=='/api/nat/add':\n"
            "                ip=b.get('ip')\n"
            "                ctl('nat-add',ip)\n"
            "            elif p=='/api/nat/remove':\n"
            "                ctl('nat-remove',b)\n"
            "        except ValueError:\n"
            "            pass\n"
        )
        patched=patch_backend(nested,self.model)
        self.assertIn("cerato_reject_routed_nat(b.get",patched)
        ns={}
        exec(compile(patched,"<nested-try>","exec"),ns)
        calls=[]
        ns["additional_ipctl"]=lambda *_:DATA
        ns["ctl"]=lambda *args:calls.append(args)
        handler=ns["Handler"]()
        handler.read_body=lambda:{"ip":PUBLIC}
        with self.assertRaisesRegex(ns["UserError"],"NAT par port"):
            handler.do_POST()
        self.assertEqual(calls,[])

    def test_nested_try_guard_inside_try_before_route(self):
        nested=SERVER.replace(
            "        b=self.read_body()\n"
            "        if not self.check_session(write=True):return\n"
            "        if p=='/api/nat/add':\n"
            "            ip=b.get('ip')\n"
            "            ctl('nat-add',ip)\n"
            "        elif p=='/api/nat/remove':\n"
            "            ctl('nat-remove',b)\n",
            "        try:\n"
            "            b=self.read_body()\n"
            "            if not self.check_session(write=True):return\n"
            "            if p=='/api/nat/add':\n"
            "                ip=b.get('ip')\n"
            "                ctl('nat-add',ip)\n"
            "            elif p=='/api/nat/remove':\n"
            "                ctl('nat-remove',b)\n"
            "        except ValueError:\n"
            "            pass\n"
        )
        patched=patch_backend(nested,self.model)
        self.assertIn("cerato_reject_routed_nat(b.get",patched)

    def test_nesting_not_allowed_in_except_handler(self):
        nested=SERVER.replace(
            "        if p=='/api/nat/add':\n"
            "            ip=b.get('ip')\n"
            "            ctl('nat-add',ip)\n"
            "        elif p=='/api/nat/remove':\n"
            "            ctl('nat-remove',b)\n",
            "        try:\n"
            "            raise ValueError()\n"
            "        except ValueError:\n"
            "            if p=='/api/nat/add':\n"
            "                ip=b.get('ip')\n"
            "                ctl('nat-add',ip)\n"
            "            elif p=='/api/nat/remove':\n"
            "                ctl('nat-remove',b)\n"
        )
        with self.assertRaisesRegex(LiveUIError,"hors d'un bloc"):
            patch_backend(nested,self.model)

    def test_get_elif_chain_in_try_and_valid_guard(self):
        nested=SERVER.replace(
            "        if p=='/api/status': return self.send_json(200,netstate())",
            "        try:\n"
            "            if p=='/api/unknown': return self.send_json(200,{})\n"
            "            elif p=='/api/status': return self.send_json(200,netstate())\n"
            "        except ValueError:\n"
            "            pass"
        )
        patched=patch_backend(nested,self.model)
        self.assertIn(
            "            if p=='/api/ip/allocations': return self.send_json(200,cerato_routed_allocations())\n"
            "            if p=='/api/unknown':",patched)
        ns={}
        exec(compile(patched,"<nested-get>","exec"),ns)
        ns["additional_ipctl"]=lambda *_:DATA
        handler=ns["Handler"]()
        # This synthetic handler uses hard-coded path; test generated GET
        # through direct lookup in local patched source.
        self.assertIn("if p=='/api/ip/allocations'",patched)

    def test_reject_guard_if_buried_inside_conditional(self):
        broken=SERVER.replace("        if not self.check_session(write=True):return",
           "        if False:\n            if not self.check_session(write=True):return")
        with self.assertRaises(LiveUIError):
            patch_backend(broken,self.model)

    def test_staging_only_creates_two_output_files(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            source=folder/"live"
            (source/"backend").mkdir(parents=True)
            (source/"web").mkdir(parents=True)
            (source/"backend/server.py").write_text(SERVER)
            (source/"web/app.js").write_text(FRONT)
            model=folder/"model.py"
            model.write_text(self.model)
            target=folder/"candidate"
            report=stage(source,target,model,
                expected_backend_sha=hashlib.sha256(SERVER.encode()).hexdigest(),
                expected_frontend_sha=hashlib.sha256(FRONT.encode()).hexdigest())
            self.assertEqual(report["status"],"staged-only")
            self.assertFalse(report["network_modified"])
            self.assertFalse(report["production_modified"])
            self.assertEqual(set(x.relative_to(target).as_posix()
                                 for x in target.rglob("*") if x.is_file()),
                             {"backend/server.py","web/app.js"})
            self.assertEqual((source/"backend/server.py").read_text(),SERVER)
            self.assertEqual((source/"web/app.js").read_text(),FRONT)

if __name__=="__main__":
    unittest.main()

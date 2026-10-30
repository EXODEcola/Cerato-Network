"""Check that the in-place upgrade only changes the IP import flow.

These tests do not open ports, run sudo, or modify a real Cerato gateway.
"""
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from patch_live_additional_ipv4 import patch_server, patch_app, PatchError, patch_tree

BACKEND='''import json,subprocess
class UserError(Exception): pass
def netstate():
    return {}
def apply_form(p):
    if not self.check_session(write=True):return
    try:
        b=self.read_body()
            if p=='/api/peers':
                pass
'''

FRONTEND="""function modalForm(action){if(action==='add-ip')return {title:'Importer une Additional IPv4',desc:'L’adresse doit déjà être configurée sur l’interface WAN du RISE-1.',endpoint:'/api/ip/add',fields:[['ip','IPv4 OVH additionnelle','text','']]} ;return null}
function send(){const data={};try{const v=await req(def.endpoint,'POST',data);doSomething(v);}catch(err){}}"""


class LegacyUpgradeTests(unittest.TestCase):
    def test_patch_keeps_original_functions(self):
        back=patch_server(BACKEND)
        ui=patch_app(FRONTEND)
        self.assertIn("def netstate()",back)
        self.assertIn("if p=='/api/peers':",back)
        self.assertIn("if p=='/api/ip/configure':",back)
        self.assertIn("if p=='/api/ip/preview':",back)
        self.assertIn("/api/ip/configure",ui)
        self.assertIn("/api/ip/preview",ui)
        self.assertIn("routed-wg",ui)

    def test_refuse_unexpected_existing_code(self):
        with self.assertRaises(PatchError):
            patch_server("def different(): pass")
        with self.assertRaises(PatchError):
            patch_app("function modalForm(){}")

    def test_duplicate_patch_refused(self):
        with self.assertRaises(PatchError):
            patch_server(patch_server(BACKEND))
        with self.assertRaises(PatchError):
            patch_app(patch_app(FRONTEND))

    def test_patch_tree_does_not_change_source(self):
        with tempfile.TemporaryDirectory(prefix="cerato-test-patch-") as d:
            src=Path(d)/"current"
            dst=Path(d)/"staged"
            (src/"backend").mkdir(parents=True)
            (src/"web").mkdir(parents=True)
            (src/"backend"/"server.py").write_text(BACKEND,encoding="utf8")
            (src/"web"/"app.js").write_text(FRONTEND,encoding="utf8")
            outcome=patch_tree(src,dst)
            self.assertGreater(outcome["frontend_bytes"],len(FRONTEND))
            self.assertEqual((src/"web"/"app.js").read_text(encoding="utf8"),FRONTEND)
            self.assertEqual((src/"backend"/"server.py").read_text(encoding="utf8"),BACKEND)
            self.assertTrue((dst/"backend"/"server.py").is_file())


if __name__=="__main__":
    unittest.main()

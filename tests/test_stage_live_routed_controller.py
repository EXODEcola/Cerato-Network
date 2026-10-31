"""Offline tests of the exact-hash RISE-1 controller staging patch.

No privileged commands; fixture has the same AST integration points as the
observed controller, but does not replace or call the real ceratoctl.
"""
from __future__ import annotations
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import stage_live_routed_controller as stage

SYNTHETIC="""from __future__ import annotations
def render_nft(data):
    entries = [data["raw_nft"]]
    return "".join(entries)
def rewrite_wg_peers(data):
    original=data["wg_text"]
    temp=data["output_sink"]
    temp.write_text(original)
"""

WG="""[Interface]
PrivateKey = SYNTHETIC-NEVER-SHARE
[Peer]
PublicKey = EXAMPLE-KEY-DELL
AllowedIPs = 10.77.0.2/32
"""
NFT="""table ip cerato_network {
 chain prerouting {
  type nat hook prerouting priority dstnat; policy accept;
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
 }
 chain forward {
  type filter hook forward priority -30; policy accept;
  iifname "enp1s0f0" oifname "wg-cerato" ct status dnat accept
  iifname "enp1s0f0" oifname "wg-cerato" drop
  iifname "wg-cerato" oifname "enp1s0f0" ct state established,related accept
  iifname "wg-cerato" oifname "enp1s0f0" drop
 }
 chain input {
  type filter hook input priority -30; policy accept;
  iifname "enp1s0f0" ip daddr 54.37.165.151 drop
 }
}
"""

class Sink:
    def __init__(self):self.value=None
    def write_text(self,value):self.value=value


def config():
    return {
        "management_ipv4":"51.210.223.57","wan_if":"enp1s0f0","wg_if":"wg-cerato",
        "routed_ipv4":[{"ip":"54.37.165.151","peer":"dell-r530"}],
        "peers":{"dell-r530":{"ip":"10.77.0.2","pubkey":"EXAMPLE-KEY-DELL"}},
        "pool":["54.37.165.151"],"mappings":[],
        "raw_nft":NFT,"wg_text":WG,"output_sink":Sink()}


class StagingTests(unittest.TestCase):
    def _env(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        home=Path(t.name)
        source=home/"controller"
        source.write_text(SYNTHETIC,encoding="utf-8")
        helper=home/"support"
        helper.mkdir()
        for name in stage.STAGING_FILES:
            (helper/name).write_bytes((ROOT/"network"/name).read_bytes())
        dest=home/"patched"
        sha=hashlib.sha256(source.read_bytes()).hexdigest()
        return home,source,helper,dest,sha

    def test_transform_does_not_evaluate_live_script(self):
        raw=SYNTHETIC.encode()
        output=stage.transform(raw)
        self.assertIn(b"routed_render_nft",output)
        self.assertIn(b"routed_extend_wg",output)
        self.assertIn(b"from cerato_routed_support import",output)
        self.assertIn(b"output_sink",output)
        self.assertNotIn(b"exec(",output)

    def test_stage_copy_executes_pure_compat_in_sandbox(self):
        home,source,helper,dest,sha=self._env()
        with patch.object(stage,"SOURCE",source),patch.object(
                stage,"EXPECTED_CONTROLLER_SHA",sha):
            report=stage.stage(source,dest,helper,sha)
        self.assertEqual(report["status"],"staged-only")
        self.assertFalse(report["ready_to_install"])
        self.assertFalse(report["network_modified"])
        self.assertTrue((dest/"cerato_routed_support.py").is_file())
        patched=(dest/"ceratoctl").read_bytes()
        sandbox={}
        # Python will import support modules from the test repo's network dir.
        # No WireGuard/nftables commands run in this test.
        sys.path.insert(0,str(ROOT/"network"))
        self.addCleanup(lambda: sys.path.remove(str(ROOT/"network")))
        import live_routed_compat as compat
        import types
        support=types.ModuleType("cerato_routed_support")
        support.routed_render_nft=compat.routed_render_nft
        support.routed_extend_wg=compat.routed_extend_wg
        with patch.dict(sys.modules,{"cerato_routed_support":support}):
            exec(compile(patched,"<synthetic-stage>","exec"),sandbox)
        data=config()
        changed=sandbox["render_nft"](data)
        self.assertIn('ip daddr 54.37.165.151 accept',changed)
        sandbox["rewrite_wg_peers"](data)
        self.assertIn("10.77.0.2/32, 54.37.165.151/32",data["output_sink"].value)
        clean={**data,"routed_ipv4":[],"output_sink":Sink()}
        self.assertEqual(sandbox["render_nft"](clean),NFT)
        sandbox["rewrite_wg_peers"](clean)
        self.assertEqual(clean["output_sink"].value,WG)
        self.assertEqual(source.read_text(),SYNTHETIC)

    def test_mismatched_hash_refuses_before_copy(self):
        home,source,helper,dest,sha=self._env()
        with patch.object(stage,"SOURCE",source),patch.object(
                stage,"EXPECTED_CONTROLLER_SHA",sha):
            with self.assertRaises(stage.StageError):
                stage.stage(source,dest,helper,"0"*64)
        self.assertFalse(dest.exists())

    def test_unknown_write_structure_refused(self):
        wrong=SYNTHETIC.replace("temp.write_text(original)","pass")
        with self.assertRaisesRegex(stage.StageError,"Écriture"):
            stage.transform(wrong.encode())

    def test_duplicate_or_complex_renderer_refused(self):
        with self.assertRaises(stage.StageError):
            stage.transform((SYNTHETIC+"\ndef render_nft(data):return 'x'\n").encode())
        with self.assertRaises(stage.StageError):
            stage.transform(SYNTHETIC.replace("return \"\".join(entries)","pass").encode())


if __name__=="__main__":
    unittest.main()

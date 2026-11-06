"""Legacy Cerato IP status-only patch: synthetic, network-independent tests."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from patch_live_ipctl_status import patched_source,StatusPatchError,MARKER

LEGACY="""#!/usr/bin/env python3
import json
class IPError(Exception): pass
CONFIG={"pool":["54.37.165.151"],"peers":{"dell-r530":{}},
        "mappings":[],"routed_ipv4":[{"ip":"54.37.165.151","peer":"dell-r530"}]}
MANAGED={"schema":1,"local_ipv4":[],
         "routed_ipv4":[{"ip":"54.37.165.151","peer":"dell-r530","wan":"wan0"}]}
WAN_ACTIVE={"51.210.223.57"}
def read_config(): return CONFIG
def effective_wan(cfg): return ("wan0","51.210.223.57")
def listed(wan): return WAN_ACTIVE
def state_read(): return MANAGED
def status():
    cfg=read_config()
    wan,primary=effective_wan(cfg)
    active=listed(wan)
    state=state_read()
    return {"wan":wan,"primary_ipv4":primary,
            "managed":[{"ip":r["ip"],"mode":"local-nat","present":r["ip"] in active}
                       for r in state["local_ipv4"]],
            "pool":cfg["pool"],"mappings":len(cfg["mappings"])}
def restore(): return "original restore preserved"
def main(): return status()
if __name__=="__main__":
    print(json.dumps(main()))
"""

class LiveIPStatusPatchTests(unittest.TestCase):
    def patched(self):
        source=patched_source(LEGACY,require_baseline=False)
        env={"__name__":"test_ipctl"}
        exec(compile(source,"<synthetic-ipctl>","exec"),env)
        return source,env

    def test_routed_state_visible_without_changing_other_commands(self):
        source,env=self.patched()
        result=env["status"]()
        self.assertEqual(result["managed"],[{
            "ip":"54.37.165.151","mode":"routed-wg",
            "peer":"dell-r530","present_on_wan":False}])
        self.assertEqual(env["restore"](),"original restore preserved")
        self.assertIn(MARKER,source)
        self.assertIn('def restore(): return "original restore preserved"',source)
        self.assertNotIn("nft(",source)
        self.assertNotIn("systemctl",source)

    def test_reject_mismatch_with_config(self):
        _,env=self.patched()
        env["CONFIG"]["routed_ipv4"]=[]
        with self.assertRaisesRegex(env["IPError"],"différents"):
            env["status"]()

    def test_reject_wan_alias(self):
        _,env=self.patched()
        env["WAN_ACTIVE"].add("54.37.165.151")
        with self.assertRaises(env["IPError"]):
            env["status"]()

    def test_reject_nat_conflict(self):
        _,env=self.patched()
        env["CONFIG"]["mappings"].append({"public_ip":"54.37.165.151"})
        with self.assertRaisesRegex(env["IPError"],"NAT"):
            env["status"]()

    def test_reject_invalid_legacy_input(self):
        with self.assertRaisesRegex(StatusPatchError,"Empreinte"):
            patched_source(LEGACY)
        with self.assertRaises(StatusPatchError):
            patched_source("def status(): return {}",require_baseline=False)

    def test_idempotency_refuses_duplicate_patch(self):
        source,_=self.patched()
        with self.assertRaisesRegex(StatusPatchError,"déjà présent"):
            patched_source(source,require_baseline=False)

if __name__=="__main__":
    unittest.main()

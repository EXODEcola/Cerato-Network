"""Read-only nft hook analysis of competing DROP and ACCEPT base chains."""
from pathlib import Path
import sys
import json
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from inspect_nft_forwarding_path import inventory,InventoryError

def record_chain(family,table,name,hook,prio,policy):
    return {"chain":{"family":family,"table":table,"name":name,"hook":hook,
                     "prio":prio,"policy":policy,"type":"filter"}}

def record_rule(family,table,chain,action):
    return {"rule":{"family":family,"table":table,"chain":chain,
                    "expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},
                                      "right":"enp1s0f0"}},{action:None}]}}


class NftPathInventoryTests(unittest.TestCase):
    def test_gateway_detects_other_forward_drop_even_with_cerato_accept(self):
        raw=json.dumps({"nftables":[
            record_chain("ip","cerato_network","forward","forward",-30,"accept"),
            record_chain("inet","filter","FORWARD","forward",0,"drop"),
            record_rule("ip","cerato_network","forward","accept"),
            record_rule("inet","filter","FORWARD","drop"),
        ]})
        result=inventory(raw,"gateway")
        self.assertEqual(len(result["chains"]),2)
        self.assertEqual(result["other_base_chains_with_possible_drop"],[
            "filter/FORWARD"])
        self.assertEqual(result["chains"][0]["accept_rules"],1)
        self.assertFalse(result["risk_is_proven_packet_loss"])
        self.assertFalse(result["ready_to_activate"])
        self.assertFalse(result["network_modified"])
        self.assertNotIn("enp1s0f0",str(result))

    def test_peer_detects_input_drop_chains_but_not_unrelated_forward(self):
        raw=json.dumps({"nftables":[
            record_chain("ip","cerato_peer_public","input","input",-50,"accept"),
            record_chain("inet","security","input","input",0,"accept"),
            record_chain("ip","other","forward","forward",0,"drop"),
            record_rule("inet","security","input","reject"),
        ]})
        result=inventory(raw,"peer")
        self.assertEqual(len(result["chains"]),2)
        self.assertEqual(result["other_base_chains_with_possible_drop"],[
            "security/input"])
        self.assertNotIn("other/forward",str(result))

    def test_drop_policy_and_duplicate_chains(self):
        raw={"nftables":[record_chain("ip","main","INPUT","input",0,"drop")]}
        out=inventory(json.dumps(raw),"peer")
        self.assertIn("main/INPUT",out["other_base_chains_with_possible_drop"])
        raw["nftables"].append(raw["nftables"][0])
        with self.assertRaises(InventoryError):
            inventory(json.dumps(raw),"peer")

    def test_unknown_syntax_and_roles_fail_closed(self):
        for raw in ("not JSON","[]","{}"):
            with self.assertRaises(InventoryError):
                inventory(raw,"gateway")
        with self.assertRaises(InventoryError):
            inventory('{"nftables":[]}',"operator")


if __name__=="__main__":
    unittest.main()

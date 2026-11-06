"""Read-only current NAT runtime audit tests with nft -j synthetic rules."""
from __future__ import annotations
from pathlib import Path
import sys
import json
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from inspect_live_nat_8080 import inspect, chains_and_rules, DiagnosticError


def sample():
    return {"nftables":[
        {"chain":{"family":"ip","table":"cerato_network","name":"prerouting",
                  "type":"nat","hook":"prerouting","prio":-100}},
        {"chain":{"family":"ip","table":"cerato_network","name":"forward",
                  "type":"filter","hook":"forward","prio":-30}},
        {"rule":{"family":"ip","table":"cerato_network","chain":"prerouting","expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},
                      "right":"54.37.165.151"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},
                      "right":8080}},
            {"dnat":{"addr":"10.77.0.2","port":8080}}]}},
        {"rule":{"family":"ip","table":"cerato_network","chain":"forward","expr":[
            {"match":{"op":"==","left":{"ct":{"key":"status"}},"right":"dnat"}},
            {"accept":None}]}},
        {"rule":{"family":"ip","table":"cerato_network","chain":"forward","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},
                      "right":"enp1s0f0"}},
            {"match":{"op":"==","left":{"meta":{"key":"oifname"}},
                      "right":"wg-cerato"}},
            {"drop":None}]}}
    ]}


def fake_read(args):
    calls={
        ("nft","-j","list","table","ip","cerato_network"):json.dumps(sample()),
        ("ip","-j","-4","route","get","10.77.0.2"):
            '[{"dst":"10.77.0.2","dev":"wg-cerato","src":"10.77.0.1"}]',
        ("ip","-j","-4","address","show","dev","enp1s0f0"):
            '[{"ifname":"enp1s0f0","addr_info":[{"local":"54.37.165.151","prefixlen":32}]}]',
        ("sysctl","-n","net.ipv4.ip_forward"):"1\n",
    }
    return calls[tuple(args)]


class NatAuditTests(unittest.TestCase):
    def test_exact_kernel_nat_hook_and_wg_route(self):
        result=inspect(fake_read)
        self.assertTrue(result["nft"]["prerouting_nat_hook"])
        self.assertEqual(result["nft"]["nat_target_rule_count"],1)
        self.assertTrue(result["route_to_dell_uses_wg"])
        self.assertTrue(result["wan_alias_present"])
        self.assertTrue(result["tcp_8080_configured_in_kernel"])
        self.assertTrue(result["ipv4_forward_enabled"])
        self.assertFalse(result["configuration_modified"])
        self.assertFalse(result["network_modified"])
        self.assertEqual(result["nft"]["forward_rule_order"][0]["ct_dnat"],True)
        self.assertNotIn("src",json.dumps(result))

    def test_unmatched_port_or_missing_nat_detected(self):
        spec=sample()
        rule=spec["nftables"][2]["rule"]["expr"]
        rule[1]["match"]["right"]=443
        output=chains_and_rules(json.dumps(spec))
        self.assertEqual(output["nat_target_rule_count"],0)

    def test_nat_duplicate_is_not_treated_as_valid(self):
        spec=sample()
        spec["nftables"].append(spec["nftables"][2])
        def read(args):
            if args[0]=="nft":
                return json.dumps(spec)
            return fake_read(args)
        r=inspect(read)
        self.assertEqual(r["nft"]["nat_target_rule_count"],2)
        self.assertFalse(r["tcp_8080_configured_in_kernel"])

    def test_error_handling(self):
        with self.assertRaises(DiagnosticError):
            chains_and_rules("not-json")
        with self.assertRaises(DiagnosticError):
            chains_and_rules('{"nftables":{}}')


if __name__=="__main__":
    unittest.main()

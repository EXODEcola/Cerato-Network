"""Check recursive nft chain inspection does not mistake jumps for terminal verdicts."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from inspect_nft_chain_jumps import inspect,InspectionError


def chain(name,*,hook=None,policy=None):
    row={"family":"ip","table":"filter","name":name}
    if hook is not None:
        row.update({"hook":hook,"policy":policy or "accept","prio":0})
    return {"chain":row}


def rule(chain_name,*expr):
    return {"rule":{"family":"ip","table":"filter","chain":chain_name,
                    "expr":list(expr)}}


class RecursiveNftInspectionTests(unittest.TestCase):
    def test_dell_one_input_rule_jumps_to_drop(self):
        data={"nftables":[chain("INPUT",hook="input"),chain("ts-input"),
                         rule("INPUT",{"jump":{"target":"ts-input"}}),
                         rule("ts-input",{"match":{"left":"secret"}},{"drop":None})]}
        result=inspect(json.dumps(data),"peer")
        entry=result["chains"][0]
        self.assertEqual(entry["immediate_rule_count"],1)
        self.assertEqual(entry["jump_or_goto_links"],1)
        self.assertEqual(entry["reachable_chain_names"],["INPUT","ts-input"])
        self.assertEqual(entry["reachable_drop_rules"],1)
        self.assertTrue(entry["potential_drop_in_reachable_chains"])
        self.assertNotIn("secret",json.dumps(result))
        self.assertFalse(result["drop_proven"])

    def test_unrelated_other_hook_not_included(self):
        data={"nftables":[chain("INPUT",hook="input"),chain("unrelated"),
                         rule("unrelated",{"drop":None}),
                         rule("INPUT",{"counter":None})]}
        result=inspect(json.dumps(data),"peer")
        entry=result["chains"][0]
        self.assertEqual(entry["reachable_chain_names"],["INPUT"])
        self.assertEqual(entry["reachable_drop_rules"],0)
        self.assertFalse(entry["potential_drop_in_reachable_chains"])

    def test_multilevel_and_cycle_terminate(self):
        data={"nftables":[chain("INPUT",hook="input"),chain("A"),chain("B"),
                         rule("INPUT",{"jump":{"target":"A"}}),
                         rule("A",{"goto":{"target":"B"}}),
                         rule("B",{"jump":{"target":"A"}},{"reject":None})]}
        entry=inspect(json.dumps(data),"peer")["chains"][0]
        self.assertEqual(entry["jump_or_goto_links"],3)
        self.assertEqual(entry["reachable_reject_rules"],1)

    def test_missing_target_flags_uncertainty(self):
        data={"nftables":[chain("INPUT",hook="input"),
                         rule("INPUT",{"jump":{"target":"not_found"}})]}
        entry=inspect(json.dumps(data),"peer")["chains"][0]
        self.assertEqual(entry["unresolved_targets"],["not_found"])
        self.assertTrue(entry["dynamic_verdicts_possible"])

    def test_invalid_data_fails_closed(self):
        for value in ("not-json","[]",json.dumps({"nftables":[
                chain("INPUT",hook="input"),chain("INPUT",hook="input")]})):
            with self.subTest(value=value),self.assertRaises(InspectionError):
                inspect(value,"peer")


if __name__=="__main__":
    unittest.main()

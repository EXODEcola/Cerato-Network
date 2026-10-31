"""Peer /32 plan unit tests. No root or system modifications."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from peer_transaction_plan import PeerTarget,PeerObserved,PeerPlanError,render_peer_stage


class PeerStageTests(unittest.TestCase):
    def setUp(self):
        self.target=PeerTarget("54.37.165.151","10.77.0.2","wg-cerato",51820,1101)
        self.obs=PeerObserved(True,None,True,True,True,True,True)

    def test_add_and_reversible_actions_only(self):
        plan=render_peer_stage(self.target,self.obs)
        self.assertTrue(plan["ready"])
        self.assertFalse(plan["executed"])
        self.assertFalse(plan["persistent"])
        self.assertEqual(plan["operations"],[
            ["ip","-4","address","add","54.37.165.151/32","dev","wg-cerato"],
            ["ip","-4","rule","add","pref","1101","from","54.37.165.151/32","table","51820"]
        ])
        self.assertEqual(plan["rollback"][0][:4],["ip","-4","rule","del"])
        self.assertEqual(plan["rollback"][1][:4],["ip","-4","address","del"])
        self.assertTrue(plan["requires_external_independent_watchdog"])
        self.assertTrue(plan["requires_explicit_gateway_cutover"])
        self.assertNotIn("192.168.128.1",str(plan))
        self.assertNotIn("nft",str(plan))
        self.assertNotIn("systemctl",str(plan))

    def test_missing_any_prerequisite_blocks_all_commands(self):
        for field in ("vpn_ip_on_tunnel","source_vpn_uses_tunnel",
                      "routing_table_has_default_wg","priority_available",
                      "rp_filter_non_strict","access_recovery_tested"):
            obs=replace(self.obs,**{field:False})
            plan=render_peer_stage(self.target,obs)
            self.assertFalse(plan["ready"])
            self.assertEqual(plan["operations"],[])
            self.assertIn(field,plan["issues"])
        plan=render_peer_stage(self.target,replace(self.obs,public_ip_owner="eno1"))
        self.assertIn("public_ip_unassigned",plan["issues"])

    def test_rejects_invalid_peer_ip_and_route_settings(self):
        for update in ({"public_ip":"10.77.0.2"},{"vpn_ip":"8.8.8.8"},
                       {"tunnel":"wg0;rm"},{"route_table":254},
                       {"rule_priority":5210}):
            with self.assertRaises(PeerPlanError):
                render_peer_stage(replace(self.target,**update),self.obs)

    def test_nonboolean_preconditions_fail_closed(self):
        with self.assertRaises(PeerPlanError):
            render_peer_stage(self.target,replace(self.obs,access_recovery_tested="yes"))


if __name__=="__main__":
    unittest.main()

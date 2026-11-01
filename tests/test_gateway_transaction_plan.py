"""Tests of fail-closed OVH gateway routability checks."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from gateway_transaction_plan import GatewayTarget,GatewayObserved,GatewayPlanError,plan_gateway


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.target=GatewayTarget("54.37.165.151","51.210.223.57","10.77.0.2",
                                  "enp1s0f0","wg-cerato")
        self.state=GatewayObserved(True,True,True,True,True,True,0,True,True,True,True)

    def test_all_checkmarks_do_not_enable_remote_cutover(self):
        result=plan_gateway(self.target,self.state)
        self.assertEqual(result["management_ip_preserved"],"51.210.223.57")
        self.assertEqual(result["blockers"],[])
        self.assertFalse(result["allow_apply"])
        self.assertFalse(result["changes_existing_wan_alias"])
        self.assertFalse(result["changes_existing_wireguard_config"])

    def test_current_nat_is_explicit_blocker(self):
        result=plan_gateway(self.target,replace(self.state,nat_mapping_count=1))
        self.assertIn("no_active_nat_mapping",result["blockers"])
        self.assertTrue(result["requires_nat_transaction_with_rollback"])
        self.assertFalse(result["allow_apply"])

    def test_missing_rollbacks_and_firewall_review_block(self):
        state=replace(self.state,forward_rules_reviewed=False,
                      independent_rollback_armed=False,peer_is_online=False)
        result=plan_gateway(self.target,state)
        for item in ("forward_rules_reviewed","independent_rollback_armed","peer_is_online"):
            self.assertIn(item,result["blockers"])

    def test_never_migrate_management_ip(self):
        with self.assertRaises(GatewayPlanError):
            plan_gateway(replace(self.target,public_ip="51.210.223.57"),self.state)
        with self.assertRaises(GatewayPlanError):
            plan_gateway(replace(self.target,wan="enp1s0f0;bad"),self.state)
        with self.assertRaises(GatewayPlanError):
            plan_gateway(self.target,replace(self.state,nat_mapping_count=-1))

if __name__=="__main__":
    unittest.main()

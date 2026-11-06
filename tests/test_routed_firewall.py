"""Routed firewall snippets are restricted to a verified /32 and do not apply."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from routed_firewall import routed_rules,FirewallPreviewError

ARGS=dict(wan="enp1s0f0",wg="wg-cerato",management_ip="51.210.223.57",
    assignments=[{"ip":"54.37.165.151","peer":"dell-r530"}],
    peers={"dell-r530":{"ip":"10.77.0.2","pubkey":"TEST-KEY"}},
    legacy_nat_mappings=[])


class RoutedFirewallTests(unittest.TestCase):
    def test_exact_inbound_outbound_rules_and_no_nat_or_flush(self):
        preview=routed_rules(**ARGS)
        self.assertEqual(preview["forward_before_wan_drop"],[
            'iifname "enp1s0f0" oifname "wg-cerato" ip daddr 54.37.165.151 accept'])
        self.assertEqual(preview["forward_before_wg_drop"],[
            'iifname "wg-cerato" oifname "enp1s0f0" ip saddr 54.37.165.151 accept'])
        self.assertFalse(preview["execution_supported"])
        self.assertFalse(preview["live_network_modified"])
        self.assertNotIn("51.210.223.57",str(preview["forward_before_wan_drop"]))
        self.assertNotIn("TEST-KEY",str(preview))
        self.assertNotIn("flush",str(preview))
        self.assertNotIn("dnat",str(preview).lower())

    def test_cannot_migrate_while_nat_rule_is_still_active(self):
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"legacy_nat_mappings":[
                {"public_ip":"54.37.165.151","public_port":8080}]}))

    def test_cannot_use_ovh_management_ip(self):
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"assignments":[
                {"ip":"51.210.223.57","peer":"dell-r530"}]}))

    def test_duplicate_public_ip_or_unknown_peer_refused(self):
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"assignments":ARGS["assignments"]*2}))
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"assignments":[
                {"ip":"54.37.165.151","peer":"unknown"}]}))

    def test_exact_multiple_public_ips_are_sorted(self):
        v=routed_rules(**(ARGS|{"assignments":[
            {"ip":"54.37.165.152","peer":"dell-r530"},
            {"ip":"54.37.165.151","peer":"dell-r530"}]}))
        self.assertEqual(len(v["forward_before_wan_drop"]),2)
        self.assertIn("54.37.165.151",v["forward_before_wan_drop"][0])
        self.assertIn("54.37.165.152",v["forward_before_wan_drop"][1])

    def test_rejects_invalid_interface_and_non_global_ip(self):
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"wan":"x; flush ruleset"}))
        with self.assertRaises(FirewallPreviewError):
            routed_rules(**(ARGS|{"assignments":[{"ip":"10.77.0.2","peer":"dell-r530"}]}))


if __name__=="__main__":
    unittest.main()

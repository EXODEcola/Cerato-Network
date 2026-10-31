import base64
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from plan import Plan,NetworkPlanError

KEY=base64.b64encode(bytes(range(32))).decode()
KEY2=base64.b64encode(bytes(range(32,64))).decode()

class NetworkPlanTests(unittest.TestCase):
    def setUp(self):
        self.plan=Plan(wan_iface="eth0",tunnel_iface="wg-cerato",
                       gateway_tunnel_ip="10.80.0.1",cidr="10.80.0.0/24",
                       primary_ipv4="9.9.9.9")
        # Use globally routable IPv4 as test-only placeholders. Never route them.
        self.plan.add_peer("node-1","10.80.0.2",KEY)

    def test_duplicate_ips_and_keys_fail(self):
        with self.assertRaises(NetworkPlanError):
            self.plan.add_peer("node-2","10.80.0.2",KEY2)
        with self.assertRaises(NetworkPlanError):
            self.plan.add_peer("node-2","10.80.0.3",KEY)

    def test_requires_provider_assignment_and_wan_detection(self):
        with self.assertRaises(NetworkPlanError):
            self.plan.add_public_ip("8.8.8.8",provider_confirmed=False,present_on_wan=True)
        with self.assertRaises(NetworkPlanError):
            self.plan.add_public_ip("8.8.8.8",provider_confirmed=True,present_on_wan=False)
        self.plan.add_public_ip("8.8.8.8",provider_confirmed=True,present_on_wan=True)
        self.assertIn("8.8.8.8",self.plan.extra_ips)

    def test_preview_refuses_unsafe_ports_and_duplicates(self):
        self.plan.add_public_ip("8.8.8.8",provider_confirmed=True,present_on_wan=True)
        with self.assertRaises(NetworkPlanError):
            self.plan.publish("8.8.8.8","node-1","tcp",22,22)
        self.plan.publish("8.8.8.8","node-1","tcp",8080,8080)
        with self.assertRaises(NetworkPlanError):
            self.plan.publish("8.8.8.8","node-1","tcp",8080,8081)
        rules=self.plan.nft_text()
        self.assertIn("dnat to 10.80.0.2:8080",rules)
        self.assertNotIn("flush ruleset",rules)
        self.assertNotIn("chain forward",rules)

    def test_routed_public_ipv4_has_no_nat_ports_and_requires_agent_rollback(self):
        self.plan.add_public_ip("8.8.8.8",provider_confirmed=True,present_on_wan=True)
        self.plan.route_public_ip("8.8.8.8","node-1")
        result=self.plan.routed_preview()
        self.assertEqual(result["mode"],"routed-wg")
        self.assertFalse(result["applicable"])
        self.assertEqual(result["gateway"][0]["public_cidr"],"8.8.8.8/32")
        self.assertEqual(result["gateway"][0]["require_peer_allowed_ips"],
                         ["10.80.0.2/32","8.8.8.8/32"])
        self.assertTrue(result["agents"][0]["preserve_existing_default_route"])
        self.assertTrue(result["agents"][0]["host_firewall_controls_exposed_ports"])
        self.assertIn("backup_and_timed_rollback_required",result["safety"])
        self.assertIn("routed_public_ipv4",self.plan.serializable())
        self.assertNotIn("dnat",self.plan.nft_text().lower())
        # There is deliberately no per-port mapping in routed /32 mode.
        with self.assertRaises(NetworkPlanError):
            self.plan.publish("8.8.8.8","node-1","tcp",8080,8080)

    def test_routed_assignment_is_exclusive_and_requires_validated_pool(self):
        with self.assertRaises(NetworkPlanError):
            self.plan.route_public_ip("8.8.8.8","node-1")
        self.plan.add_public_ip("8.8.8.8",provider_confirmed=True,present_on_wan=True)
        with self.assertRaises(NetworkPlanError):
            self.plan.route_public_ip("8.8.8.8","unknown")
        self.plan.publish("8.8.8.8","node-1","tcp",8080,8080)
        with self.assertRaises(NetworkPlanError):
            self.plan.route_public_ip("8.8.8.8","node-1")
        self.plan.publications.clear()
        self.plan.route_public_ip("8.8.8.8","node-1")
        with self.assertRaises(NetworkPlanError):
            self.plan.route_public_ip("8.8.8.8","node-1")
        self.assertEqual(len(self.plan.routed_preview()["gateway"]),1)

    def test_reject_injection_and_outside_cidr(self):
        with self.assertRaises(NetworkPlanError):
            Plan(wan_iface='eth0"; flush ruleset',tunnel_iface="wg0",
                 cidr="10.80.0.0/24",gateway_tunnel_ip="10.80.0.1",
                 primary_ipv4="8.8.4.4")
        with self.assertRaises(NetworkPlanError):
            self.plan.add_peer("bad;name","10.80.0.3",KEY2)
        with self.assertRaises(NetworkPlanError):
            self.plan.add_peer("node-2","10.81.0.4",KEY2)

if __name__=="__main__":
    unittest.main()

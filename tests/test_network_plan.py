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
                       primary_ipv4="203.0.113.10")
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

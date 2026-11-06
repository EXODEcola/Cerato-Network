"""Dell host public /32 INPUT filtering preview tests (pure, no nft calls)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from dell_public_firewall import preview,PublicFirewallPlanError


class DellPublicFirewallTests(unittest.TestCase):
    def test_public_22_default_drop_only_on_routed_tunnel_ip(self):
        plan=preview("54.37.165.151","wg-cerato")
        raw=plan["nft_script"]
        self.assertFalse(plan["applied"])
        self.assertFalse(plan["ready_for_install"])
        self.assertIn('iifname "wg-cerato" ip daddr 54.37.165.151 tcp dport 22 accept',raw)
        self.assertIn('iifname "wg-cerato" ip daddr 54.37.165.151 drop',raw)
        self.assertLess(raw.index("tcp dport 22 accept"),raw.index("54.37.165.151 drop"))
        self.assertNotIn("flush",raw)
        self.assertNotIn("51.210.223.57",raw)
        self.assertNotIn("10.77.0.2",raw)
        self.assertNotIn("tailscale0",raw)
        self.assertNotIn("eno1",raw)

    def test_explicit_service_ports_are_sorted_and_restricted(self):
        plan=preview("54.37.165.151","wg-cerato",tcp_ports=(8080,22,443),udp_ports=(19132,))
        self.assertEqual(plan["allow_tcp"],[22,443,8080])
        self.assertEqual(plan["allow_udp"],[19132])
        self.assertIn("udp dport 19132 accept",plan["nft_script"])
        self.assertNotIn("udp dport 53",plan["nft_script"])

    def test_no_ssh_or_duplicate_ports_fail_closed(self):
        for kwargs in ({"tcp_ports":(8080,)},
                       {"tcp_ports":(22,22)},
                       {"udp_ports":(19132,19132)},
                       {"tcp_ports":(22,65536)},
                       {"tcp_ports":("22",)},
                       {"wg":"wg-cerato; flush ruleset"},
                       {"public_ip":"10.77.0.2"}):
            args={"public_ip":"54.37.165.151","wg":"wg-cerato"}
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(PublicFirewallPlanError):
                preview(**args)


if __name__=="__main__":
    unittest.main()

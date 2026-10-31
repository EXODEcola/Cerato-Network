"""Legacy RISE-1 firewall overlay contract, no privileged operations."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from routed_nft_inject import inject_routed_forward, LegacyFirewallError

IP="54.37.165.151"
WAN="enp1s0f0"
WG="wg-cerato"
SAMPLE="""table ip cerato_network {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
        }
        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
        }
        chain forward {
                type filter hook forward priority -30; policy accept;
                iifname "enp1s0f0" oifname "wg-cerato" ct status dnat accept
                iifname "enp1s0f0" oifname "wg-cerato" drop
                iifname "wg-cerato" oifname "enp1s0f0" ct state established,related accept
                iifname "wg-cerato" oifname "enp1s0f0" drop
        }
        chain input {
                type filter hook input priority -30; policy accept;
                iifname "enp1s0f0" ip daddr 54.37.165.151 drop
        }
}
"""
def render(raw=SAMPLE,*,assignments=None,legacy_nat_mappings=None):
    if assignments is None:
        assignments=[{"ip":IP,"peer":"dell-r530"}]
    if legacy_nat_mappings is None:
        legacy_nat_mappings=[]
    return inject_routed_forward(
        raw,wan=WAN,wg=WG,management_ip="51.210.223.57",
        peers={"dell-r530":{"ip":"10.77.0.2","pubkey":"TEST-SECRET"}},
        assignments=assignments,legacy_nat_mappings=legacy_nat_mappings)


class LegacyRoutedNftTests(unittest.TestCase):
    def test_injects_before_both_default_drops_without_touching_old_guards(self):
        actual=render()
        first='iifname "enp1s0f0" oifname "wg-cerato" ip daddr 54.37.165.151 accept'
        second='iifname "wg-cerato" oifname "enp1s0f0" ip saddr 54.37.165.151 accept'
        inbound='iifname "enp1s0f0" oifname "wg-cerato" drop'
        outbound='iifname "wg-cerato" oifname "enp1s0f0" drop'
        self.assertLess(actual.index(first),actual.index(inbound))
        self.assertLess(actual.index(second),actual.index(outbound))
        self.assertEqual(actual.count("chain forward {"),1)
        self.assertEqual(actual.count("chain input {"),1)
        self.assertEqual(actual.count("ip daddr 54.37.165.151 drop"),1)
        self.assertEqual(actual.count("ct status dnat accept"),1)
        self.assertNotIn("TEST-SECRET",actual)
        self.assertNotIn("flush ruleset",actual)
        self.assertNotIn("51.210.223.57",actual)

    def test_no_routed_ip_is_exact_legacy_passthrough(self):
        self.assertEqual(render(assignments=[]),SAMPLE)

    def test_rejects_duplicate_wan_drop(self):
        changed=SAMPLE.replace(
            'iifname "enp1s0f0" oifname "wg-cerato" drop',
            'iifname "enp1s0f0" oifname "wg-cerato" drop\n'
            '                iifname "enp1s0f0" oifname "wg-cerato" drop')
        with self.assertRaises(LegacyFirewallError):
            render(changed)

    def test_rejects_missing_input_drop(self):
        with self.assertRaisesRegex(LegacyFirewallError,"INPUT"):
            render(SAMPLE.replace('iifname "enp1s0f0" ip daddr 54.37.165.151 drop',''))

    def test_rejects_active_nat_for_routed_ip(self):
        with self.assertRaises(LegacyFirewallError):
            render(SAMPLE,legacy_nat_mappings=[
                {"public_ip":IP,"public_port":8080,"proto":"tcp"}])
        old_nat=('iifname "enp1s0f0" ip daddr 54.37.165.151 tcp dport 8080 '
                 'dnat to 10.77.0.2:8080\n')
        with self.assertRaisesRegex(LegacyFirewallError,"DNAT"):
            render(SAMPLE.replace("        chain postrouting {",old_nat+"        chain postrouting {"))

    def test_rejects_unknown_chain_order_or_priority(self):
        with self.assertRaises(LegacyFirewallError):
            render(SAMPLE.replace('priority -30','priority 0'))
        with self.assertRaises(LegacyFirewallError):
            render(SAMPLE.replace('table ip cerato_network','table inet main'))
        with self.assertRaises(LegacyFirewallError):
            render(SAMPLE.replace('chain input {','chain output {'))

    def test_rejects_arbitrary_management_ip_or_duplicate_assignment(self):
        with self.assertRaises(LegacyFirewallError):
            render(assignments=[{"ip":"51.210.223.57","peer":"dell-r530"}])
        with self.assertRaises(LegacyFirewallError):
            render(assignments=[{"ip":IP,"peer":"dell-r530"}]*2)


if __name__=="__main__":
    unittest.main()

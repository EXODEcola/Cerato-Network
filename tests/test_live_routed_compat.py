"""Compatibility of routed IPv4 to real-style Cerato WG peers and nft output."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from live_routed_compat import plans,routed_extend_wg,routed_render_nft,RoutedCompatError

PUBLIC="54.37.165.151"
DATA={
    "management_ipv4":"51.210.223.57","wan_if":"enp1s0f0","wg_if":"wg-cerato",
    "routed_ipv4":[{"ip":PUBLIC,"peer":"dell-r530"}],
    "peers":{
        "dell-r530":{"ip":"10.77.0.2","pubkey":"EXAMPLE-KEY-DELL"},
        "other":{"ip":"10.77.0.3","pubkey":"EXAMPLE-KEY-OTHER"}},
    "pool":[PUBLIC],"mappings":[]}
WG="""[Interface]
PrivateKey = FAKE-DONT-COPY
Address = 10.77.0.1/24
[Peer]
# dell-r530
PublicKey = EXAMPLE-KEY-DELL
AllowedIPs = 10.77.0.2/32
[Peer]
# other
PublicKey = EXAMPLE-KEY-OTHER
AllowedIPs = 10.77.0.3/32
"""
NFT="""table ip cerato_network {
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

class LiveCompatTests(unittest.TestCase):
    def test_no_routed_migrations_is_exact_backward_compat(self):
        data={**DATA,"routed_ipv4":[]}
        self.assertEqual(routed_extend_wg(WG,data),WG)
        self.assertEqual(routed_render_nft(NFT,data),NFT)

    def test_peer_public_allowed_ip_is_added_without_disturbing_other_peer(self):
        result=routed_extend_wg(WG,DATA)
        self.assertIn("AllowedIPs = 10.77.0.2/32, 54.37.165.151/32",result)
        self.assertIn("PublicKey = EXAMPLE-KEY-OTHER\nAllowedIPs = 10.77.0.3/32\n",result)
        self.assertIn("PrivateKey = FAKE-DONT-COPY",result)
        self.assertEqual(result.count(PUBLIC+"/32"),1)
        self.assertEqual(routed_extend_wg(result,DATA),result)

    def test_only_precise_forward_rules_added(self):
        result=routed_render_nft(NFT,DATA)
        self.assertIn('iifname "enp1s0f0" oifname "wg-cerato" ip daddr '+PUBLIC+' accept',result)
        self.assertIn('iifname "wg-cerato" oifname "enp1s0f0" ip saddr '+PUBLIC+' accept',result)
        self.assertIn('ip daddr '+PUBLIC+' drop',result)
        self.assertIn('ct status dnat accept',result)
        self.assertNotIn("flush ruleset",result)

    def test_missing_management_ip_blocks_cutover(self):
        with self.assertRaises(RoutedCompatError):
            plans({k:v for k,v in DATA.items() if k!="management_ipv4"})

    def test_nat_mapping_and_same_management_ip_block(self):
        with self.assertRaises(RoutedCompatError):
            plans({**DATA,"mappings":[{"public_ip":PUBLIC,"public_port":8080}]})
        with self.assertRaises(RoutedCompatError):
            plans({**DATA,"management_ipv4":PUBLIC})

    def test_wrong_key_missing_wg_peer_does_not_emit_bad_config(self):
        with self.assertRaises(RoutedCompatError):
            routed_extend_wg(WG.replace("EXAMPLE-KEY-DELL","DIFFERENT"),DATA)
        with self.assertRaises(RoutedCompatError):
            routed_extend_wg(WG.replace("10.77.0.2/32","10.77.0.5/32"),DATA)

    def test_rejects_duplicate_public_ip_and_invalid_peer(self):
        with self.assertRaises(RoutedCompatError):
            plans({**DATA,"routed_ipv4":DATA["routed_ipv4"]*2})
        with self.assertRaises(RoutedCompatError):
            plans({**DATA,"routed_ipv4":[{"ip":PUBLIC,"peer":"missing"}]})

if __name__=="__main__":
    unittest.main()

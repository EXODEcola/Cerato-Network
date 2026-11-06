"""Dell read-only exposure and WireGuard AllowedIPs safety tests."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from preflight_dell_exposure_cryptokey import (
    check, listeners, gateway_cryptokey, nft_input_hooks, AuditError,
)

PUB="54.37.165.151"
GW="10.77.0.1"
WG="wg-cerato"

SAMPLES={
    ("wg","show",WG,"allowed-ips"):"SYNTHETIC-WG-PUBLIC-KEY 0.0.0.0/0, ::/0\n",
    ("ss","-H","-ltn"):"LISTEN 0 256 0.0.0.0:22 0.0.0.0:*\n"
                       "LISTEN 0 256 127.0.0.53%lo:53 0.0.0.0:*\n"
                       "LISTEN 0 256 [::]:60784 [::]:*\n",
    ("ss","-H","-lun"):"UNCONN 0 0 100.74.84.71:53 0.0.0.0:*\n"
                       "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n",
    ("nft","-j","list","ruleset"):json.dumps({"nftables":[
        {"table":{"family":"inet","name":"filter"}},
        {"chain":{"family":"inet","name":"input","hook":"input","prio":0,"type":"filter"}},
        {"chain":{"family":"ip","name":"cerato","hook":"forward","type":"filter"}}]}),
    ("ip","-j","-4","address","show"):json.dumps([{
        "ifname":"wg-cerato","addr_info":[{"family":"inet","local":"10.77.0.2"}]
    },{"ifname":"eno1","addr_info":[{"family":"inet","local":"192.168.129.92"}]}]),
    ("ip","-j","-6","address","show"):json.dumps([{"ifname":"eno1","addr_info":[{
        "family":"inet6","local":"2a02:a03f:6bc1:1301:46a8:42ff:fe4a:86b6"}]}]),
}


def fake_read(args):
    return SAMPLES.get(tuple(args))


class DellExposureTests(unittest.TestCase):
    def test_full_tunnel_peer_and_listeners_are_anonymized(self):
        result=check(fake_read,public_ip=PUB,vpn_gateway_ip=GW,tunnel=WG)
        self.assertEqual(result["checks"]["unique_gateway_wireguard_peer"],"pass")
        self.assertEqual(result["checks"]["wireguard_peer_supports_full_ipv4_egress"],"pass")
        self.assertEqual(result["checks"]["public_ip_not_assigned_to_any_dell_interface"],"pass")
        self.assertEqual(result["nft_input_hook_count"],1)
        self.assertEqual(result["ipv6_input_hook_count"],1)
        self.assertEqual(result["global_ipv6_present"],True)
        self.assertEqual(result["tcp_listeners"],[
            {"port":22,"binding":"all_ipv4"},
            {"port":53,"binding":"loopback"},
            {"port":60784,"binding":"all_ipv6"}])
        self.assertEqual(result["udp_listeners"],[
            {"port":53,"binding":"nonpublic_ipv4"},
            {"port":51820,"binding":"all_ipv4"}])
        self.assertFalse(result["ready_to_activate"])
        self.assertFalse(result["network_modified"])
        self.assertFalse(result["public_ipv4_firewall_confirmed"])
        self.assertNotIn("SYNTHETIC-WG-PUBLIC-KEY",json.dumps(result))
        self.assertNotIn("192.168.129.92",json.dumps(result))
        self.assertNotIn("2a02:a03f",json.dumps(result))

    def test_gateway_only_peer_is_not_sufficient_for_public_egress(self):
        result=gateway_cryptokey("FAKE-KEY 10.77.0.1/32\n",GW)
        self.assertEqual(result["gateway_peer_unique"],"pass")
        self.assertEqual(result["internet_allowed_ips"],"block")

    def test_multiple_matching_peers_are_rejected(self):
        self.assertEqual(gateway_cryptokey(
            "KEY-A 10.77.0.1/32\nKEY-B 0.0.0.0/0\n",GW)["gateway_peer_unique"],"block")
        self.assertEqual(gateway_cryptokey(None,GW)["internet_allowed_ips"],"unknown")

    def test_absent_sys_tools_are_unknown_and_not_ready(self):
        result=check(lambda _:None,public_ip=PUB,vpn_gateway_ip=GW,tunnel=WG)
        self.assertEqual(result["checks"]["nftables_ruleset_inspected"],"unknown")
        self.assertEqual(result["checks"]["wireguard_peer_supports_full_ipv4_egress"],"unknown")
        self.assertIsNone(result["tcp_listeners"])
        self.assertFalse(result["ready_to_activate"])

    def test_nft_count_is_not_firewall_approval(self):
        result=nft_input_hooks(SAMPLES[("nft","-j","list","ruleset")])
        self.assertEqual(result["input_hooks"],1)
        self.assertEqual(result["ip6_input_hooks"],1)
        self.assertFalse(nft_input_hooks("not json")["readable"])

    def test_public_ip_already_assigned_is_blocked(self):
        def read(args):
            if args==["ip","-j","-4","address","show"]:
                return json.dumps([{"ifname":"wg-cerato","addr_info":[
                    {"local":PUB,"family":"inet"}]}])
            return fake_read(args)
        report=check(read,public_ip=PUB,vpn_gateway_ip=GW,tunnel=WG)
        self.assertEqual(report["checks"]["public_ip_not_assigned_to_any_dell_interface"],"block")

    def test_invalid_interface_and_targets_refused(self):
        for config in ({"public_ip":"10.77.0.2"},
                       {"vpn_gateway_ip":PUB},{"tunnel":"wg0; rm -rf /"}):
            opts={"public_ip":PUB,"vpn_gateway_ip":GW,"tunnel":WG}
            opts.update(config)
            with self.assertRaises(AuditError):
                check(fake_read,**opts)


if __name__=="__main__":
    unittest.main()

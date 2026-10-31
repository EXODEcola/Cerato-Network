"""Tests sans root du preflight IPv4 / WireGuard, avec commandes simulées."""
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from preflight_public_ipv4 import (
    address_set, check, public_ipv4, private_ipv4, wg_peer_state,
)


PUB = "8.8.4.4"
PEER = "10.77.0.2"
WG = "wg-cerato"
WAN = "ens3"


class FakeRead:
    def __init__(self, *, routed=False, public_on_wan=True,
                 public_on_peer=False, active=True, port_listening=True):
        self.calls = []
        self.routed = routed
        self.public_on_wan = public_on_wan
        self.public_on_peer = public_on_peer
        self.active = active
        self.port_listening = port_listening

    def __call__(self, argv):
        self.calls.append(tuple(argv))
        if argv == ["ip", "link", "show", "dev", WG]:
            return "wg-cerato up"
        if argv == ["ip", "-4", "rule", "show"]:
            return ("0: from all lookup local\n"
                    "1100: from 10.77.0.2 lookup 51820\n"
                    + ("1200: from 8.8.4.4 lookup 51820\n" if self.public_on_peer else "")
                    + "5210: from all fwmark 0x80000/0xff0000 lookup main\n"
                    + "5270: from all lookup 52\n")
        if argv == ["sysctl", "-n", "net.ipv4.conf.all.rp_filter"]:
            return "2\n"
        if argv == ["sysctl", "-n", "net.ipv4.conf.wg-cerato.rp_filter"]:
            return "2\n"
        if argv == ["ip", "-j", "-4", "addr", "show", "dev", WAN]:
            return json.dumps([{"addr_info": [
                {"family": "inet", "local": PUB}]}] if self.public_on_wan
                else [{"addr_info": []}])
        if argv == ["ip", "-j", "-4", "addr", "show", "dev", WG]:
            values = [PEER]
            if self.public_on_peer:
                values.append(PUB)
            return json.dumps([{"addr_info": [
                {"family": "inet", "local": ip} for ip in values]}])
        if argv == ["sysctl", "-n", "net.ipv4.ip_forward"]:
            return "1\n"
        if argv == ["ip", "-j", "-4", "route", "get", PEER]:
            return '[{"dev":"wg-cerato"}]'
        if argv == ["ip", "-j", "-4", "route", "get", PUB]:
            return '[{"dev":"wg-cerato"}]' if self.routed else '[{"dev":"lo"}]'
        if argv == ["ip", "-j", "-4", "route", "get", "1.1.1.1", "from", PEER]:
            return '[{"dev":"wg-cerato"}]' if self.routed else '[{"dev":"eno1"}]'
        if argv == ["ip", "-j", "-4", "route", "get", "1.1.1.1", "from", PUB]:
            return '[{"dev":"wg-cerato"}]' if self.routed else '[{"dev":"ens3"}]'
        if argv == ["wg", "show", WG, "allowed-ips"]:
            return "FAKE-PUBLIC-KEY\t10.77.0.2/32\n"
        if argv == ["wg", "show", WG, "latest-handshakes"]:
            return ("FAKE-PUBLIC-KEY\t" +
                    str(int(time.time()) if self.active else 0) + "\n")
        if argv == ["nft", "-a", "list", "ruleset"]:
            return ("ip daddr 8.8.4.4 tcp dport 8080 dnat to 10.77.0.2:8080\n"
                    "ip daddr 8.8.4.4 tcp dport 8081 dnat to 10.77.0.3:8081")
        if argv == ["ss", "-H", "-ltn", "sport", "=", ":8080"]:
            return "LISTEN 0 128 0.0.0.0:8080\n" if self.port_listening else ""
        raise RuntimeError("unavailable")


class PreflightTests(unittest.TestCase):
    def by_code(self, report):
        return {item["code"]: item for item in report["checks"]}

    def test_local_nat_reports_8080_without_claiming_ssh_or_public_ownership(self):
        fake = FakeRead()
        result = check(fake, "gateway", PUB, WG, PEER, WAN, "local-nat", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["nat_rule"]["status"], "ok")
        self.assertEqual(findings["wan_address"]["status"], "ok")
        self.assertEqual(findings["peer_route"]["status"], "ok")
        self.assertFalse(result["modifications"])
        self.assertNotIn("FAKE-PUBLIC-KEY", str(result))
        self.assertNotIn("vérifié", findings["nat_rule"]["message"])

    def test_routed_ip_exposes_conflicting_local_address_and_missing_route(self):
        fake = FakeRead()
        result = check(fake, "gateway", PUB, WG, PEER, WAN, "routed-wg", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["wan_address"]["status"], "attention")
        self.assertEqual(findings["public_route"]["status"], "attention")

    def test_peer_detects_vpn_table_and_loose_rp_filter(self):
        fake = FakeRead(routed=True)
        result = check(fake, "peer", PUB, WG, PEER, None, "local-nat", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["vpn_source_policy"]["status"], "ok")
        self.assertIn("51820", findings["vpn_source_policy"]["message"])
        self.assertEqual(findings["rp_filter"]["status"], "ok")
        self.assertIn("souple", findings["rp_filter"]["message"])
        self.assertEqual(findings["nat_return_route"]["status"], "ok")
        self.assertNotIn("0x80000", str(result))

    def test_routed_public_ip_requires_distinct_source_rule(self):
        fake = FakeRead(routed=True, public_on_peer=False)
        result = check(fake, "peer", PUB, WG, PEER, None, "routed-wg", 8080)
        self.assertEqual(self.by_code(result)["public_source_policy"]["status"], "attention")
        fake = FakeRead(routed=True, public_on_peer=True)
        result = check(fake, "peer", PUB, WG, PEER, None, "routed-wg", 8080)
        self.assertEqual(self.by_code(result)["public_source_policy"]["status"], "ok")

    def test_local_nat_peer_flags_asymmetric_reply_without_assuming_snat(self):
        fake = FakeRead(routed=False)
        result = check(fake, "peer", PUB, WG, PEER, None, "local-nat", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["nat_return_route"]["status"], "attention")
        self.assertIn("sans SNAT", findings["nat_return_route"]["message"])
        fake = FakeRead(routed=True)
        result = check(fake, "peer", PUB, WG, PEER, None, "local-nat", 8080)
        self.assertEqual(self.by_code(result)["nat_return_route"]["status"], "ok")

    def test_peer_requires_public_alias_and_return_route(self):
        fake = FakeRead(routed=False, public_on_peer=False)
        result = check(fake, "peer", PUB, WG, PEER, None, "routed-wg", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["public_on_peer"]["status"], "attention")
        self.assertEqual(findings["source_route"]["status"], "attention")

    def test_peer_routed_ready_is_still_not_end_to_end_proof(self):
        fake = FakeRead(routed=True, public_on_peer=True)
        result = check(fake, "peer", PUB, WG, PEER, None, "routed-wg", 8080)
        findings = self.by_code(result)
        self.assertEqual(findings["source_route"]["status"], "ok")
        self.assertEqual(findings["public_on_peer"]["status"], "ok")
        self.assertIn("ne prouve pas", result["limitation"])

    def test_missing_permissions_do_not_crash(self):
        fake = FakeRead()
        def fail_nft(argv):
            if argv[0] == "nft":
                raise RuntimeError("permission denied")
            return fake(argv)
        result = check(fail_nft, "gateway", PUB, WG, PEER, WAN,
                       "local-nat", 8080)
        self.assertEqual(self.by_code(result)["nat_rule"]["status"], "unknown")

    def test_no_invalid_public_or_tunnel_ips(self):
        from argparse import ArgumentTypeError
        for invalid in ("10.77.0.2", "not-ip", "2001:db8::1"):
            with self.assertRaises(ArgumentTypeError):
                public_ipv4(invalid)
        with self.assertRaises(ArgumentTypeError):
            private_ipv4("8.8.8.8")


if __name__ == "__main__":
    unittest.main()

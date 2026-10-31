"""Unit contract for routed public IPv4 readiness (no network calls)."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "network"))
from routed_readiness import (
    GatewayObservation, PeerObservation, Recovery, ReadinessError, assess
)


def complete():
    return (
        GatewayObservation(True, True, True, True, True, 0, True),
        PeerObservation(True, True, 2, True, True, True, True, True),
        Recovery(True, True, True, True, True, True),
    )


def run(g=None, p=None, r=None):
    full = complete()
    return assess("54.37.165.151", "10.77.0.2", "enp1s0f0", "wg-cerato",
                  g if g is not None else full[0],
                  p if p is not None else full[1],
                  r if r is not None else full[2])


class ReadinessTests(unittest.TestCase):
    def test_all_observed_ready_does_not_apply_network(self):
        out = run()
        self.assertEqual(out["mode"], "routed-wg")
        self.assertEqual(out["public_ip"], "54.37.165.151")
        self.assertEqual(out["blockers"], [])
        self.assertTrue(out["ready_for_review"])
        self.assertFalse(out["apply_allowed"])
        self.assertFalse(out["enabled"])
        self.assertTrue(out["post_deploy_validation_required"])

    def test_realistic_dell_and_gateway_still_blocked(self):
        gateway = GatewayObservation(True, False, True, True, True, 1, False)
        peer = PeerObservation(True, True, 2, True, False, False, True, False)
        recovery = Recovery(False, True, False, False, False, False)
        out = run(gateway, peer, recovery)
        self.assertIn("agent_online", out["blockers"])
        self.assertIn("nat_migration_plan", out["blockers"])
        self.assertIn("signed_compatibility", out["blockers"])
        self.assertIn("peer_firewall_review", out["blockers"])
        self.assertIn("provider_attached", out["blockers"])
        self.assertFalse(out["ready_for_review"])

    def test_an_ssh_server_listening_is_not_ssh_hardening(self):
        g, p, r = complete()
        p = replace(p, ssh_keys_only=False)
        out = run(p=p)
        self.assertIn("ssh_keys_only", out["blockers"])

    def test_rp_filter_strict_is_blocker(self):
        g, p, r = complete()
        p = replace(p, rp_filter_effective=1)
        out = run(p=p)
        self.assertIn("peer_rp_filter_non_strict", out["blockers"])

    def test_tailscale_and_existing_default_route_must_remain_available(self):
        g, p, r = complete()
        out = run(p=replace(p, trusted_recovery_access=False,
                            existing_default_route_preserved=False))
        self.assertIn("recovery_access", out["blockers"])
        self.assertIn("peer_default_route_preserved", out["blockers"])

    def test_fails_closed_on_no_backup_or_watchdog(self):
        g, p, r = complete()
        out = run(r=replace(r, backup_verified=False, gateway_watchdog=False))
        self.assertIn("verified_backup", out["blockers"])
        self.assertIn("gateway_watchdog", out["blockers"])

    def test_fails_closed_with_live_nat_mapping(self):
        g, p, r = complete()
        out = run(g=replace(g, live_nat_mappings=1))
        self.assertIn("nat_migration_plan", out["blockers"])

    def test_validates_observations(self):
        g, p, r = complete()
        with self.assertRaises(ReadinessError):
            run(p=replace(p, rp_filter_effective=3))
        with self.assertRaises(ReadinessError):
            run(g=replace(g, live_nat_mappings=-1))
        with self.assertRaises(ReadinessError):
            run(p=replace(p, ssh_listening="yes"))
        with self.assertRaises(ReadinessError):
            assess("10.77.0.5", "10.77.0.2", "enp1s0f0", "wg-cerato", g, p, r)
        with self.assertRaises(ReadinessError):
            assess("54.37.165.151", "10.77.0.2", "wg-cerato", "wg-cerato", g, p, r)


if __name__ == "__main__":
    unittest.main()

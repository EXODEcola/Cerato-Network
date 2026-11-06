"""Two-host /32 transaction protocol tests. Pure state, no operating-system calls."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from two_host_cutover_contract import (
    Protocol, ProtocolError, EVENTS, HEALTH, describe, observe,
    authorize_operator, transition, verify
)

BASE={"transaction_id":"a"*32,"public_ip":"54.37.165.151",
      "management_ip":"51.210.223.57"}


def complete_plan():
    p=Protocol(**BASE)
    for host,events in EVENTS.items():
        for event in events:
            p=observe(p,host,event)
    return p


class TwoHostCutoverProtocolTests(unittest.TestCase):
    def test_new_transaction_is_blocked_and_does_not_arm_watchdogs(self):
        p=Protocol(**BASE)
        r=describe(p)
        self.assertEqual(r["phase"],"plan")
        self.assertFalse(r["authorization_to_apply"])
        self.assertFalse(r["agent_installed"])
        self.assertFalse(r["watchdog_actually_armed"])
        self.assertFalse(r["live_network_modified"])
        self.assertIn("peer.firewall_reviewed",r["remaining_prepare"])
        self.assertIn("peer.ipv6_exposure_reviewed",r["remaining_prepare"])
        with self.assertRaises(ProtocolError):
            transition(p,"prepare")
        with self.assertRaises(ProtocolError):
            transition(p,"arm")

    def test_all_host_preconditions_and_external_checks_are_required(self):
        p=complete_plan()
        p=transition(p,"prepare")
        with self.assertRaises(ProtocolError):
            transition(p,"arm")
        p=authorize_operator(p,True)
        p=transition(p,"arm")
        p=transition(p,"start_cutover")
        p=transition(p,"start_verification")
        for check in sorted(HEALTH)[:-1]:
            p=verify(p,check)
        with self.assertRaisesRegex(ProtocolError,"externes"):
            transition(p,"commit")
        p=verify(p,sorted(HEALTH)[-1])
        p=transition(p,"commit")
        self.assertEqual(p.phase,"committed")
        self.assertEqual(describe(p)["remaining_commit_checks"],[])
        self.assertFalse(describe(p)["authorization_to_apply"])
        with self.assertRaises(ProtocolError):
            transition(p,"rollback")

    def test_ipv6_review_and_both_independent_watchdogs_are_mandatory(self):
        for missing in ("peer.ipv6_exposure_reviewed","peer.firewall_reviewed",
                        "gateway.watchdog_armed","peer.watchdog_armed",
                        "gateway.rollback_drill_passed","peer.rollback_drill_passed",
                        "peer.tailscale_recovery_tested"):
            p=complete_plan()
            p=replace(p,proofs=p.proofs-{missing})
            with self.subTest(missing=missing),self.assertRaises(ProtocolError):
                transition(p,"prepare")

    def test_nonfinal_failure_requires_explicit_rollback(self):
        p=transition(complete_plan(),"prepare")
        p=authorize_operator(p,True)
        p=transition(p,"arm")
        p=transition(p,"start_cutover")
        p=transition(p,"rollback")
        self.assertEqual(p.phase,"rollback_required")
        with self.assertRaises(ProtocolError):
            transition(p,"commit")
        p=transition(p,"rollback_confirmed")
        self.assertEqual(p.phase,"rolled_back")
        with self.assertRaises(ProtocolError):
            transition(p,"start_cutover")

    def test_validation_rejects_management_public_collision_and_bad_times(self):
        for args in ({"transaction_id":"not-random"},
                     {"management_ip":"54.37.165.151"},
                     {"public_ip":"10.77.0.2"},
                     {"deadline_seconds":0},
                     {"deadline_seconds":3600},
                     {"deadline_seconds":True},
                     {"operator_authorized":"yes"},
                     {"phase":"deployed"}):
            params={**BASE,**args}
            with self.subTest(args=args),self.assertRaises(ProtocolError):
                Protocol(**params)

    def test_unknown_or_wrong_host_proof_and_early_verification_denied(self):
        p=Protocol(**BASE)
        for host,event in (("gateway","firewall_reviewed"),
                           ("peer","watchdog_executed"),
                           ("owner","watchdog_armed")):
            with self.subTest(host=host,event=event),self.assertRaises(ProtocolError):
                observe(p,host,event)
        with self.assertRaises(ProtocolError):
            verify(p,"external_ipv4_ingress_success")
        with self.assertRaises(ProtocolError):
            transition(p,"rollback_confirmed")


if __name__=="__main__":
    unittest.main()

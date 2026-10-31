"""All cutover failure points roll back both pure host snapshots."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from two_host_rollback_rehearsal import (
    STEPS, RehearsalError, rehearse, report
)


class TwoHostRollbackTests(unittest.TestCase):
    def test_every_failure_point_restores_gateway_peer_and_recovery(self):
        for step in STEPS:
            with self.subTest(step=step):
                result=report(rehearse(fail_after=step))
                self.assertEqual(result["result"],"simulated_rolled_back")
                self.assertEqual(result["failure_injected_at"],step)
                self.assertTrue(result["gateway_restored_in_memory"])
                self.assertTrue(result["peer_restored_in_memory"])
                self.assertTrue(result["gateway_management_preserved_in_memory"])
                self.assertTrue(result["peer_tailscale_preserved_in_memory"])
                self.assertEqual(result["rollback_order"],[
                    "gateway_local_snapshot_restored",
                    "peer_local_snapshot_restored"])
                self.assertFalse(result["network_modified"])
                self.assertFalse(result["agents_installed"])
                self.assertFalse(result["rollout_authorized"])

    def test_simulated_success_is_not_a_real_cutover_or_external_probe(self):
        result=report(rehearse())
        self.assertEqual(result["result"],"simulated_ready_for_external_probes")
        self.assertEqual(result["steps_attempted"],list(STEPS))
        self.assertFalse(result["external_connectivity_proven"])
        self.assertFalse(result["agents_installed"])
        self.assertFalse(result["rollout_authorized"])
        self.assertFalse(result["network_modified"])
        self.assertEqual(result["rollback_order"],[])

    def test_unknown_stage_does_not_run(self):
        with self.assertRaises(RehearsalError):
            rehearse(fail_after="delete_default_route")


if __name__=="__main__":
    unittest.main()

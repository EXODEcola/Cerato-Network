"""Two-state routed IPv4 agreement must block stale NAT and WAN alias restores."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from routed_state_agreement import StateAgreementError,agreed_renderer_config

PUBLIC="54.37.165.151"
BASE={
    "wan_if":"enp1s0f0","wg_if":"wg-cerato","pool":[PUBLIC],
    "peers":{"dell-r530":{"ip":"10.77.0.2","pubkey":"EXAMPLE-KEY"}},
    "mappings":[],"routed_ipv4":[{"ip":PUBLIC,"peer":"dell-r530"}]
}
MANAGED={"schema":1,"local_ipv4":[],
         "routed_ipv4":[{"ip":PUBLIC,"peer":"dell-r530","wan":"enp1s0f0"}]}


class AgreementTests(unittest.TestCase):
    def test_matching_state_produces_copy_without_changing_inputs(self):
        controller=copy.deepcopy(BASE)
        managed=copy.deepcopy(MANAGED)
        result=agreed_renderer_config(controller,managed,
                                      observed_primary_ip="51.210.223.57")
        self.assertEqual(result["management_ipv4"],"51.210.223.57")
        self.assertNotIn("management_ipv4",controller)
        self.assertEqual(controller,BASE)
        self.assertEqual(managed,MANAGED)
        self.assertEqual(result["routed_ipv4"],BASE["routed_ipv4"])

    def test_legacy_no_routes_stays_backward_compatible(self):
        result=agreed_renderer_config(
            {**BASE,"routed_ipv4":[]},
            {"schema":1,"local_ipv4":[{"ip":PUBLIC,"wan":"enp1s0f0"}]},
            observed_primary_ip="51.210.223.57")
        self.assertEqual(result["routed_ipv4"],[])
        self.assertEqual(result["management_ipv4"],"51.210.223.57")

    def test_persisted_but_uncommitted_route_fails_closed(self):
        with self.assertRaisesRegex(StateAgreementError,"différent"):
            agreed_renderer_config(
                {**BASE,"routed_ipv4":[]},MANAGED,
                observed_primary_ip="51.210.223.57")
        with self.assertRaisesRegex(StateAgreementError,"différent"):
            agreed_renderer_config(
                BASE,{"schema":1,"local_ipv4":[]},
                observed_primary_ip="51.210.223.57")

    def test_stale_alias_and_nat_mapping_refuse_routed_mode(self):
        stale={**MANAGED,"local_ipv4":[{"ip":PUBLIC,"wan":"enp1s0f0"}]}
        with self.assertRaisesRegex(StateAgreementError,"alias"):
            agreed_renderer_config(BASE,stale,
                                   observed_primary_ip="51.210.223.57")
        with self.assertRaisesRegex(StateAgreementError,"invalide"):
            agreed_renderer_config(
                {**BASE,"mappings":[{"public_ip":PUBLIC,"public_port":8080}]},
                MANAGED,observed_primary_ip="51.210.223.57")

    def test_primary_ip_and_peer_wan_cannot_be_swapped(self):
        with self.assertRaisesRegex(StateAgreementError,"principale"):
            agreed_renderer_config(
                {**BASE,"routed_ipv4":[{"ip":"51.210.223.57","peer":"dell-r530"}]},
                {**MANAGED,"routed_ipv4":[{
                    "ip":"51.210.223.57","peer":"dell-r530","wan":"enp1s0f0"}]},
                observed_primary_ip="51.210.223.57")
        with self.assertRaisesRegex(StateAgreementError,"WAN"):
            agreed_renderer_config(
                BASE,{**MANAGED,"routed_ipv4":[{
                    "ip":PUBLIC,"peer":"dell-r530","wan":"wrong-wan"}]},
                observed_primary_ip="51.210.223.57")
        with self.assertRaisesRegex(StateAgreementError,"gestion"):
            agreed_renderer_config(
                {**BASE,"management_ipv4":"8.8.8.8"},
                MANAGED,observed_primary_ip="51.210.223.57")

    def test_duplicate_routes_fail_closed(self):
        with self.assertRaisesRegex(StateAgreementError,"deux fois"):
            agreed_renderer_config(
                {**BASE,"routed_ipv4":BASE["routed_ipv4"]*2},
                MANAGED,observed_primary_ip="51.210.223.57")


if __name__=="__main__":
    unittest.main()

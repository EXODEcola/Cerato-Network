"""Read-only IPv4 pool allocation rendering contract.

These tests prevent a routed Dell /32 from ever being presented as
available or as a per-port NAT destination. No live networking.
"""
from __future__ import annotations
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"network"))
from routed_ui_status import summarize,RoutedUIError

PUBLIC="54.37.165.151"
BASE={
    "wan":"enp1s0f0",
    "primary_ipv4":"51.210.223.57",
    "pool":[PUBLIC],
    "managed":[{"ip":PUBLIC,"mode":"routed-wg",
                "peer":"dell-r530","present_on_wan":False}],
    "mappings":0
}

class RoutedUIStatusTests(unittest.TestCase):
    def test_routed_dell_ip_is_allocated_without_local_wan_alias_or_nat(self):
        config=copy.deepcopy(BASE)
        status=summarize(config)
        self.assertEqual(status["schema"],"cerato-ipv4-allocations-v1")
        self.assertEqual(status["total"],1)
        self.assertEqual(status["allocated_count"],1)
        self.assertEqual(status["available_count"],0)
        self.assertEqual(status["routed_count"],1)
        self.assertEqual(status["nat_publications"],0)
        self.assertEqual(status["entries"][0]["mode"],"routed-wg")
        self.assertEqual(status["entries"][0]["peer"],"dell-r530")
        self.assertFalse(status["entries"][0]["can_remove"])
        self.assertEqual(config,BASE)

    def test_empty_pool_and_unmanaged_address(self):
        a=copy.deepcopy(BASE)
        a["managed"]=[]
        result=summarize(a)
        self.assertEqual(result["allocated_count"],0)
        self.assertEqual(result["available_count"],1)
        self.assertTrue(result["entries"][0]["can_remove"])
        self.assertEqual(result["entries"][0]["label"],"Disponible")

    def test_local_address_missing_from_wan_remains_reserved(self):
        a=copy.deepcopy(BASE)
        a["managed"]=[{"ip":PUBLIC,"mode":"local-nat","present":False}]
        result=summarize(a)
        self.assertEqual(result["available_count"],0)
        self.assertEqual(result["allocated_count"],1)
        self.assertEqual(result["warnings"],1)
        self.assertFalse(result["entries"][0]["can_remove"])

    def test_stale_wan_alias_on_routed_ip_warns_and_prevents_mutation(self):
        a=copy.deepcopy(BASE)
        a["managed"][0]["present_on_wan"]=True
        row=summarize(a)["entries"][0]
        self.assertEqual(row["state"],"warning")
        self.assertFalse(row["can_remove"])

    def test_mixed_pool_orders_addresses_and_keeps_distinct_counts(self):
        a=copy.deepcopy(BASE)
        a["pool"]=["54.37.165.160",PUBLIC,"54.37.165.155"]
        res=summarize(a)
        self.assertEqual([x["ip"] for x in res["entries"]],
                         [PUBLIC,"54.37.165.155","54.37.165.160"])
        self.assertEqual(res["allocated_count"],1)
        self.assertEqual(res["available_count"],2)
        self.assertTrue(res["entries"][2]["can_remove"])

    def test_invalid_conflicting_source_fails_closed(self):
        for bad in [
            {"managed":BASE["managed"]*2},
            {"pool":[PUBLIC,PUBLIC]},
            {"pool":[]},
            {"primary_ipv4":PUBLIC},
            {"managed":[{"ip":PUBLIC,"mode":"unknown"}]},
            {"managed":[{"ip":PUBLIC,"mode":"routed-wg","peer":"??","present_on_wan":False}]},
            {"managed":[{"ip":PUBLIC,"mode":"routed-wg","peer":"dell-r530"}]},
        ]:
            with self.subTest(bad=bad):
                state=copy.deepcopy(BASE)
                state.update(bad)
                with self.assertRaises(RoutedUIError):
                    summarize(state)

if __name__=="__main__":
    unittest.main()

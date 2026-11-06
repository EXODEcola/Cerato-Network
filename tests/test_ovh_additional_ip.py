"""Fake iproute2 tests for non-disruptive OVH Additional IPv4 operations.

No privileged ip/wg/nft commands and no real network modification.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"network"))
import ovh_additional_ip as ipctl


class AdditionalIPTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.config=self.root/"config.json"
        self.state=self.root/"managed.json"
        self.config.write_text(json.dumps({
            "wan_if":"enp1s0f0","wg_if":"wg-cerato",
            "tunnel_cidr":"10.77.0.0/24","gateway_tunnel_ip":"10.77.0.1",
            "pool":[],"mappings":[],
            "peers":{"dell-r530":{"ip":"10.77.0.2","pubkey":"valid-placeholder"}},
        }),encoding="utf8")
        self.commands=[]
        self.addresses={"51.210.223.57"}
        self.cfg=patch.object(ipctl,"CONFIG",self.config)
        self.state_patch=patch.object(ipctl,"STATE",self.state)
        self.cfg.start();self.state_patch.start()
        self.addCleanup(self.cfg.stop);self.addCleanup(self.state_patch.stop)
        self.patcher=patch.object(ipctl,"run",side_effect=self.fake_run)
        self.patcher.start();self.addCleanup(self.patcher.stop)

    def fake_run(self,*argv):
        self.commands.append(tuple(argv))
        if argv[:5]==("ip","-j","-4","route","get"):
            return json.dumps([{"dev":"enp1s0f0","prefsrc":"51.210.223.57"}])
        if argv[:5]==("ip","-j","-4","addr","show"):
            return json.dumps([{"addr_info":[{"local":ip,"family":"inet"} for ip in self.addresses]}])
        if argv[:4]==("ip","-4","address","add"):
            self.addresses.add(argv[4].split("/")[0])
            return ""
        if argv[:4]==("ip","-4","address","del"):
            self.addresses.remove(argv[4].split("/")[0])
            return ""
        raise AssertionError("Unexpected command: "+repr(argv))

    def test_add_local_address_and_persist_without_touching_wg_or_route(self):
        result=ipctl.import_local("54.37.165.151")
        self.assertTrue(result["persisted"])
        self.assertIn("54.37.165.151",self.addresses)
        saved=json.loads(self.state.read_text())
        self.assertEqual(saved["local_ipv4"][0]["ip"],"54.37.165.151")
        self.assertFalse(saved["local_ipv4"][0]["preexisting"])
        self.assertEqual(ipctl.restore()["restored"],1)
        self.assertEqual(self.commands.count(("ip","-4","address","add",
                                              "54.37.165.151/32","dev","enp1s0f0")),1)
        for argv in self.commands:
            self.assertNotIn("netplan",argv)
            self.assertNotIn("nft",argv)
            self.assertNotIn("wg",argv)
            self.assertNotIn("flush",argv)
            self.assertFalse(len(argv)>3 and argv[:3]==("ip","-4","route") and argv[3] in ("add","del","replace","flush"))

    def test_migrate_existing_pool_only_if_ip_is_present(self):
        self.addresses.add("54.37.165.151")
        cfg=json.loads(self.config.read_text(encoding="utf8"))
        cfg["pool"]=["54.37.165.151","8.8.8.8"]
        self.config.write_text(json.dumps(cfg),encoding="utf8")
        result=ipctl.adopt_existing_pool()
        self.assertEqual(result["adopted"],["54.37.165.151"])
        self.assertEqual(result["ignored_absent"],["8.8.8.8"])
        self.assertTrue(ipctl.state_read()["local_ipv4"][0]["preexisting"])
        self.assertFalse(any(x[:4]==("ip","-4","address","add") for x in self.commands))

    def test_preexisting_alias_not_deleted_when_unmanaged(self):
        self.addresses.add("54.37.165.151")
        ipctl.import_local("54.37.165.151")
        self.assertTrue(ipctl.state_read()["local_ipv4"][0]["preexisting"])
        self.assertEqual(ipctl.remove_local("54.37.165.151")["removed"],"54.37.165.151")
        self.assertIn("54.37.165.151",self.addresses)
        self.assertFalse(any(x[:4]==("ip","-4","address","del") for x in self.commands))

    def test_main_ip_must_never_be_added(self):
        with self.assertRaises(ipctl.IPError):
            ipctl.import_local("51.210.223.57")
        self.assertNotIn(("ip","-4","address","add","51.210.223.57/32","dev","enp1s0f0"),
                         self.commands)

    def test_routed_mode_is_advertised_but_never_applied(self):
        result=ipctl.preview("54.37.165.151","routed-wg")
        self.assertFalse(result["supported"])
        self.assertIn("agent Linux",result["reason"])
        self.assertFalse(any(x[:4]==("ip","-4","address","add") for x in self.commands))

    def test_reject_public_address_when_owned_by_nat_mapping(self):
        ipctl.import_local("54.37.165.151")
        cfg=json.loads(self.config.read_text())
        cfg["mappings"]=[{"public_ip":"54.37.165.151","peer":"dell-r530",
                          "proto":"tcp","public_port":8080,"target_port":8080}]
        self.config.write_text(json.dumps(cfg))
        with self.assertRaises(ipctl.IPError):
            ipctl.remove_local("54.37.165.151")
        self.assertIn("54.37.165.151",self.addresses)

    def test_routed_persistence_never_recreates_public_ip_on_wan(self):
        public="54.37.165.151"
        self.addresses.add(public)
        ipctl.import_local(public)
        cfg=json.loads(self.config.read_text())
        cfg["pool"]=[public]
        self.config.write_text(json.dumps(cfg))
        original=self.state.read_bytes()
        candidate=ipctl.plan_routed_state_after_cutover(public,"dell-r530")
        # Planning is pure; it cannot change live addresses or state.
        self.assertEqual(self.state.read_bytes(),original)
        self.assertIn(public,self.addresses)
        self.assertEqual(candidate["local_ipv4"],[])
        self.assertEqual(candidate["routed_ipv4"],[
            {"ip":public,"peer":"dell-r530","wan":"enp1s0f0"}])
        # Simulate an approved external cutover of the already moved IP.
        self.addresses.remove(public)
        ipctl.save(candidate)
        prior=len(self.commands)
        self.assertEqual(ipctl.restore()["restored"],0)
        self.assertEqual(ipctl.adopt_existing_pool()["adopted"],[])
        self.assertNotIn(public,self.addresses)
        self.assertFalse(any(cmd[:4]==("ip","-4","address","add")
                             for cmd in self.commands[prior:]))
        with self.assertRaises(ipctl.IPError):
            ipctl.import_local(public)
        managed=ipctl.status()["managed"]
        self.assertEqual(managed[0]["mode"],"routed-wg")
        self.assertEqual(managed[0]["peer"],"dell-r530")

    def test_routed_state_planner_rejects_live_nat_publication(self):
        ipctl.import_local("54.37.165.151")
        cfg=json.loads(self.config.read_text())
        cfg["pool"]=["54.37.165.151"]
        cfg["mappings"]=[{"public_ip":"54.37.165.151","proto":"tcp",
                          "public_port":8080,"target_port":8080}]
        self.config.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ipctl.IPError,"NAT active"):
            ipctl.plan_routed_state_after_cutover("54.37.165.151","dell-r530")
        self.assertEqual(ipctl.state_read()["routed_ipv4"],[])

    def test_state_rejects_local_and_routed_duplicate(self):
        public="54.37.165.151"
        self.state.write_text(json.dumps({
            "schema":1,"local_ipv4":[{"ip":public,"wan":"enp1s0f0"}],
            "routed_ipv4":[{"ip":public,"wan":"enp1s0f0","peer":"dell-r530"}]
        }))
        with self.assertRaisesRegex(ipctl.IPError,"locale et routée"):
            ipctl.state_read()

    def test_legacy_local_state_remains_compatible(self):
        public="54.37.165.151"
        self.state.write_text(json.dumps({
            "schema":1,"local_ipv4":[{"ip":public,"wan":"enp1s0f0"}]
        }))
        self.assertEqual(ipctl.state_read()["routed_ipv4"],[])
        self.assertEqual(ipctl.state_read()["local_ipv4"][0]["ip"],public)

    def test_reject_wrong_wan_without_network_changes(self):
        cfg=json.loads(self.config.read_text())
        cfg["wan_if"]="eth9"
        self.config.write_text(json.dumps(cfg))
        with self.assertRaises(ipctl.IPError):
            ipctl.import_local("54.37.165.151")
        self.assertFalse(any(x[:4]==("ip","-4","address","add") for x in self.commands))


if __name__=="__main__":
    unittest.main()

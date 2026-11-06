"""No live network writes when reconciling an already-routed /32."""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"network"))
import ovh_additional_ip as ipctl

PUBLIC="54.37.165.151"
PEER="dell-r530"
KEY="test-public-key-no-secret"

class RoutedStateAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.config=base/"config.json"
        self.state=base/"state.json"
        self.config.write_text(json.dumps({
            "wan_if":"enp1s0f0", "wg_if":"wg-cerato",
            "pool":[PUBLIC], "mappings":[],
            "peers":{PEER:{"ip":"10.77.0.2","pubkey":KEY}},
            "routed_ipv4":[{"ip":PUBLIC,"peer":PEER}],
        }))
        self.state.write_text(json.dumps({
            "schema":1,"local_ipv4":[],"routed_ipv4":[]
        }))
        for field,path in (("CONFIG",self.config),("STATE",self.state)):
            mock=patch.object(ipctl,field,path)
            mock.start();self.addCleanup(mock.stop)
        self.calls=[]
        self.wan_alias=False
        self.correct_route=True
        self.recent=True
        mock=patch.object(ipctl,"run",side_effect=self.fake_run)
        mock.start();self.addCleanup(mock.stop)

    def fake_run(self,*args):
        self.calls.append(args)
        if args==("ip","-j","-4","route","get","1.1.1.1"):
            return json.dumps([{"dev":"enp1s0f0","src":"51.210.223.57"}])
        if args==("ip","-j","-4","addr","show","dev","enp1s0f0"):
            addresses=["51.210.223.57"]+([PUBLIC] if self.wan_alias else [])
            return json.dumps([{"addr_info":[{"family":"inet","local":a}
                                              for a in addresses]}])
        if args==("ip","-j","-4","route","get",PUBLIC):
            return json.dumps([{"dev":"wg-cerato" if self.correct_route else "enp1s0f0"}])
        if args==("wg","show","wg-cerato","allowed-ips"):
            return KEY+" 10.77.0.2/32, "+PUBLIC+"/32\n"
        if args==("wg","show","wg-cerato","latest-handshakes"):
            return KEY+" "+str(int(time.time()) if self.recent else 1)+"\n"
        if args==("sysctl","-n","net.ipv4.ip_forward"):
            return "1\n"
        raise AssertionError("unexpected call: "+repr(args))

    def assert_read_only_network(self):
        self.assertFalse(any(a[0] in ("nft","systemctl") for a in self.calls))
        self.assertFalse(any(a[0] in ("wg","ip") and
                             any(op in a for op in ("set","add","del","replace","flush"))
                             for a in self.calls))

    def test_adopts_existing_routed_without_network_mutation(self):
        result=ipctl.adopt_verified_routed()
        self.assertEqual(result["status"],"adopted")
        self.assertFalse(result["network_modified"])
        self.assertEqual(ipctl.state_read()["routed_ipv4"],
                         [{"ip":PUBLIC,"peer":PEER,"wan":"enp1s0f0"}])
        self.assertEqual(ipctl.status()["managed"][0]["mode"],"routed-wg")
        self.assertEqual(ipctl.adopt_verified_routed()["status"],"already_managed")
        self.assert_read_only_network()

    def test_reconciles_old_local_record_without_wan_alias(self):
        self.state.write_text(json.dumps({
            "schema":1,"local_ipv4":[{"ip":PUBLIC,"wan":"enp1s0f0",
                                      "preexisting":True}],"routed_ipv4":[]
        }))
        self.assertEqual(ipctl.adopt_verified_routed()["status"],"adopted")
        self.assertEqual(ipctl.state_read()["local_ipv4"],[])
        self.assertEqual(ipctl.restore()["restored"],0)
        self.assert_read_only_network()

    def test_refuses_config_not_declaring_routed_ip(self):
        cfg=json.loads(self.config.read_text())
        cfg["routed_ipv4"]=[]
        self.config.write_text(json.dumps(cfg))
        before=self.state.read_bytes()
        with self.assertRaises(ipctl.IPError):
            ipctl.adopt_verified_routed()
        self.assertEqual(before,self.state.read_bytes())

    def test_refuses_wrong_interface(self):
        self.correct_route=False
        with self.assertRaisesRegex(ipctl.IPError,"Route publique"):
            ipctl.adopt_verified_routed()
        self.assertEqual(ipctl.state_read()["routed_ipv4"],[])

    def test_refuses_alias_present_on_wan(self):
        self.wan_alias=True
        with self.assertRaisesRegex(ipctl.IPError,"encore présente"):
            ipctl.adopt_verified_routed()

    def test_refuses_legacy_nat(self):
        cfg=json.loads(self.config.read_text())
        cfg["mappings"]=[{"public_ip":PUBLIC}]
        self.config.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ipctl.IPError,"NAT incompatible"):
            ipctl.adopt_verified_routed()

    def test_refuses_stale_peer(self):
        self.recent=False
        with self.assertRaisesRegex(ipctl.IPError,"Handshake"):
            ipctl.adopt_verified_routed()

    def test_refuses_contradictory_owner(self):
        self.state.write_text(json.dumps({"schema":1,"local_ipv4":[],
            "routed_ipv4":[{"ip":PUBLIC,"peer":"other-peer","wan":"enp1s0f0"}]}))
        with self.assertRaisesRegex(ipctl.IPError,"contradictoire"):
            ipctl.adopt_verified_routed()

if __name__=="__main__":
    unittest.main()

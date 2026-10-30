"""Ensure the OVH sidecar reads real WG status without ever invoking dump.

No real sudo, WireGuard, firewall, routes or OVH host are contacted.
"""
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"gateway"))
import http_api


class SafeWireGuardStatusTests(unittest.TestCase):
    def test_live_peers_read_only_without_private_key_dump(self):
        commands=[]
        peerkey="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        snapshot={
            "wan_if":"eth0", "wg_if":"wg-cerato", "wg_port":51820,
            "peers":{"dell":{"ip":"10.77.0.2","pubkey":peerkey}},
            "pool":[], "gateway_tunnel_ip":"10.77.0.1",
        }
        def mock_run(argv,**kwargs):
            commands.append(list(argv))
            if argv[-1]=="status":
                return SimpleNamespace(returncode=0,stdout=json.dumps(snapshot),stderr="")
            if argv[-1]=="latest-handshakes":
                return SimpleNamespace(returncode=0,stdout=peerkey+"\t1800000000\n",stderr="")
            if argv[-1]=="transfer":
                return SimpleNamespace(returncode=0,stdout=peerkey+"\t1234\t5678\n",stderr="")
            raise AssertionError("Unexpected privileged command: "+repr(argv))
        with patch.object(http_api.os.path,"isfile",return_value=True),patch.object(http_api.subprocess,"run",side_effect=mock_run):
            result=http_api.status_payload()
        self.assertTrue(result["tunnel_active"])
        self.assertEqual(result["peers"]["dell"]["last_handshake"],1800000000)
        self.assertEqual(result["peers"]["dell"]["received"],1234)
        self.assertEqual(result["peers"]["dell"]["sent"],5678)
        self.assertEqual(len(commands),3)
        for command in commands:
            self.assertEqual(command[:2],["sudo","-n"])
            self.assertNotIn("dump",command)
            self.assertNotIn("tunnel",command)
            self.assertNotIn("apply",command)
            self.assertNotIn("publish",command)

    def test_sudo_rejected_fails_closed(self):
        def mock_run(argv,**kwargs):
            if argv[-1]=="status":
                return SimpleNamespace(returncode=0,stdout=json.dumps({
                    "wg_if":"wg-cerato","peers":{},
                }),stderr="")
            return SimpleNamespace(returncode=1,stdout="",stderr="not permitted")
        with patch.object(http_api.os.path,"isfile",return_value=True),patch.object(http_api.subprocess,"run",side_effect=mock_run):
            result=http_api.status_payload()
        self.assertFalse(result["tunnel_active"])
        self.assertEqual(result["dashboard_mode"],"live")

    def test_sidecar_sudo_policy_never_authorizes_mutation(self):
        script=(ROOT/"scripts"/"ovh-shadow.sh").read_text(encoding="utf8")
        start=script.index('cat > "$SUDOERS" <<SUDO')
        end=script.index("\nSUDO",start)
        policy=script[start:end]
        self.assertIn("latest-handshakes",policy)
        self.assertIn(" transfer",policy)
        self.assertIn("ceratoctl status",policy)
        for forbidden in ("ceratoctl tunnel","ceratoctl apply","ceratoctl publish",
                          "ceratoctl peer-add","ceratoctl pool-add","wg show wg-cerato dump"):
            self.assertNotIn(forbidden,policy)

if __name__=="__main__":
    unittest.main()

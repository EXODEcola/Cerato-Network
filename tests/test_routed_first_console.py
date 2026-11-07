"""Routed-only UI: real state, owner/admin access and no mutating call."""
from pathlib import Path
import json
import os
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gateway import http_api as api

PUBLIC="54.37.165.151"
DATA={
  "primary_ipv4":"51.210.223.57",
  "pool":[PUBLIC],
  "managed":[{"ip":PUBLIC,"peer":"dell-r530","mode":"routed-wg",
              "present_on_wan":False}],
  "mappings":0,
}

class RoutedNetworkGatewayTests(unittest.TestCase):
    def test_privileged_read_only_model_uses_exact_status_call(self):
        calls=[]
        def fake(command,*args,**kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0,stdout=json.dumps(DATA))
        with patch.dict(os.environ,{"CERATO_DEV_AUTH_ONLY":"0"}), \
             patch.object(api.Path,"is_file",return_value=True), \
             patch.object(api.subprocess,"run",side_effect=fake):
            status=api.routed_allocations_payload()
        self.assertEqual(calls,[["sudo","-n","/usr/local/sbin/cerato-ipctl","status"]])
        self.assertEqual(status["routed_count"],1)
        self.assertEqual(status["available_count"],0)
        self.assertEqual(status["entries"][0]["peer"],"dell-r530")

    def test_isolated_auth_mode_refuses_to_call_privileged_tools(self):
        with patch.dict(os.environ,{"CERATO_DEV_AUTH_ONLY":"1"}), \
             patch.object(api.subprocess,"run") as process:
            with self.assertRaises(OSError):
                api.routed_allocations_payload()
            process.assert_not_called()

    def test_invalid_status_fails_closed(self):
        with patch.dict(os.environ,{"CERATO_DEV_AUTH_ONLY":"0"}), \
             patch.object(api.Path,"is_file",return_value=True), \
             patch.object(api.subprocess,"run",return_value=SimpleNamespace(
                 returncode=0,stdout='{"pool":["'+PUBLIC+'"],"managed":[]}')):
            with self.assertRaises(ValueError):
                api.routed_allocations_payload()

    def test_client_never_enables_legacy_port_nat_mutations(self):
        app=(ROOT/"web/app.js").read_text()
        self.assertIn("routesView(main)",app)
        self.assertIn("Routage complet /32",app)
        self.assertIn("'/api/ip/allocations'",app)
        self.assertNotIn("'/api/nat/add'",app)
        self.assertNotIn("'/api/nat/remove'",app)
        self.assertNotIn("innerHTML",app)
        self.assertNotIn("localStorage.setItem(",app)
        self.assertIn("history.pushState",app)
        self.assertIn("window.addEventListener('popstate'",app)
        self.assertIn("window.addEventListener('hashchange'",app)
        self.assertIn("if(state.account.role!=='user')",app)

if __name__=="__main__":
    unittest.main()

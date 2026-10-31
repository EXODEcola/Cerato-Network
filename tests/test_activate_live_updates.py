"""One-shot OVH signed update activation must never touch Build or network."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import activate_live_updates as m


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.a=patch.object(m,"_network_snapshot",return_value="stable")
        self.b=patch.object(m,"_prerequisites",return_value={
            "configured":False,"can_check":False})
        self.c=patch.object(m,"_json_ctl",return_value={
            "configured":True,"can_check":True,"installable":False,
            "channel":"beta"})
        self.a.start();self.b.start();self.c.start()
        self.addCleanup(self.a.stop);self.addCleanup(self.b.stop);self.addCleanup(self.c.stop)

    def test_no_key_never_provisions_or_changes_network(self):
        with patch.object(m,"provision") as provision:
            result=m.activate()
            self.assertEqual(result["status"],"source_missing")
            with self.assertRaisesRegex(m.ActivationError,"aucune clé publique"):
                m.activate(install=True)
            provision.assert_not_called()

    def test_approved_key_must_be_present_before_switch(self):
        with patch.object(m,"provision") as provision,\
             patch.object(m,"_tls_probe",return_value=False):
            result=m.activate(install=True,public_key="/tmp/test.pub",
                              fingerprint="f"*64)
            provision.assert_called_once_with(
                m.BASE_URL,Path("/tmp/test.pub"),"f"*64,"beta")
            self.assertEqual(result["status"],"waiting_for_signed_release")
            self.assertTrue(result["configured"])
            self.assertFalse(result["installable"])
            self.assertFalse(result["build_modified"])

    def test_existing_config_is_idempotent(self):
        with patch.object(m,"_prerequisites",return_value={
            "configured":True,"can_check":True}),\
             patch.object(m,"_tls_probe",return_value=True),\
             patch.object(m,"provision") as provision:
            result=m.activate()
            self.assertTrue(result["configured"])
            self.assertEqual(result["status"],"ready")
            provision.assert_not_called()

    def test_never_overwrite_previously_pinned_key(self):
        with patch.object(m,"_prerequisites",return_value={
            "configured":True,"can_check":True}),\
             patch.object(m,"provision") as provision:
            with self.assertRaisesRegex(m.ActivationError,"remplacement de clé interdit"):
                m.activate(install=True,public_key="/tmp/test.pub",
                           fingerprint="f"*64)
            provision.assert_not_called()

    def test_missing_web_update_engine_blocks_before_provision(self):
        with patch.object(m,"_prerequisites",side_effect=m.ActivationError("moteur absent")),\
             patch.object(m,"provision") as provision:
            with self.assertRaises(m.ActivationError):
                m.activate(install=True,public_key="/tmp/test.pub",
                           fingerprint="f"*64)
            provision.assert_not_called()

    def test_no_build_or_network_mutation_api(self):
        source=(ROOT/"integrations/activate_live_updates.py").read_text()
        for forbidden in ("ssh ","scp ","wg set","nft ","iptables ","systemctl restart",
                          "git pull","--signing-key","private_key"):
            self.assertNotIn(forbidden,source)


if __name__=="__main__":
    unittest.main()

"""Functional status tests for the root-owned signed-release controller.

All provider responses, files and installation commands are mocked.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
sys.path.insert(0,str(ROOT/"tools"))
import live_controller as ctl
from remote import DistributionError


class LiveUpdateStatusTests(unittest.TestCase):
    def setUp(self):
        self.state={"installed_version":"v0.0.0","history":[],"state":"ready"}
        self.config={"base_url":"https://updates.invalid/cerato","channel":"beta"}
        self.key=Path("/unused/public.pub")

    def test_unconfigured_is_not_signature_error(self):
        with patch.object(ctl,"_state",return_value=self.state),\
             patch.object(ctl,"_settings",side_effect=ctl.UpdateError("not configured")) as settings,\
             patch.object(ctl,"_save",lambda state:None),\
             patch.object(ctl,"download_channel",side_effect=AssertionError("must not download")):
            info=ctl.check()
            self.assertEqual(info["reason_code"],"source_not_configured")
            self.assertEqual(info["status"],"unconfigured")
            self.assertFalse(info["can_check"])
            self.assertFalse(info["installable"])
            self.assertNotIn("Échec de vérification",info["last_result"])
            self.assertFalse(settings.call_count<1)

    def test_equal_remote_version_is_a_normal_success(self):
        with patch.object(ctl,"_state",return_value=self.state),\
             patch.object(ctl,"_settings",return_value=(self.config,self.key)),\
             patch.object(ctl,"_save",lambda state:None),\
             patch.object(ctl,"_candidate",return_value=None),\
             patch.object(ctl,"check_channel",return_value={
                 "update_available":False,"version":"v0.0.0"}),\
             patch.object(ctl,"download_channel",side_effect=AssertionError("not newer")):
            info=ctl.check()
            self.assertTrue(info["configured"])
            self.assertEqual(info["reason_code"],"already_current")
            self.assertEqual(info["available_version"],None)
            self.assertEqual(info["status"],"current")
            self.assertIsInstance(info["last_checked_at"],int)

    def test_invalid_signed_index_is_safely_reported(self):
        with patch.object(ctl,"_state",return_value=self.state),\
             patch.object(ctl,"_settings",return_value=(self.config,self.key)),\
             patch.object(ctl,"_save",lambda state:None),\
             patch.object(ctl,"check_channel",side_effect=DistributionError(
                 "provider secret https://updates.invalid/cerato")):
            info=ctl.check()
            self.assertEqual(info["reason_code"],"release_check_failed")
            self.assertEqual(info["status"],"check_failed")
            self.assertNotIn("https://",info["last_result"])
            self.assertFalse(info["installable"])

    def test_good_release_is_shown_only_after_compatible_overlay(self):
        with patch.object(ctl,"_state",return_value=self.state),\
             patch.object(ctl,"_settings",return_value=(self.config,self.key)),\
             patch.object(ctl,"_save",lambda state:None),\
             patch.object(ctl,"check_channel",return_value={
                 "update_available":True,"version":"v0.1.0-beta.1"}),\
             patch.object(ctl,"download_channel",return_value={
                 "version":"v0.1.0-beta.1","downloaded":True}),\
             patch.object(ctl,"_candidate",return_value=Path("/mock/release")):
            info=ctl.check()
            self.assertEqual(info["reason_code"],"release_ready")
            self.assertEqual(info["available_version"],"v0.1.0-beta.1")
            self.assertTrue(info["installable"])
            self.assertTrue(info["can_check"])

if __name__=="__main__":
    unittest.main()

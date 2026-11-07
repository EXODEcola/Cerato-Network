"""The one-time OVH bootstrap must update both signed-update validators.

It must never restart Web, WG, firewall, or install a release.
"""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class RoutedMirrorBootstrapTests(unittest.TestCase):
    def test_upgrade_copies_mirror_and_web_schema_together(self):
        code=(ROOT/"scripts/upgrade-live-update-engine.sh").read_text()
        for fragment in (
            "updates/live_controller.py",
            "integrations/patch_live_routed_ui.py",
            "network/routed_ui_status.py",
            "tools/stage_signed_static_release.py",
            'grep -q \'ROUTED_SCHEMA=\' "$ROOT/updates/live_controller.py"',
            'grep -q \'ROUTED_SCHEMA=\' "$ROOT/tools/stage_signed_static_release.py"',
            'cp -p "$TARGET/$rel" "$BACKUP/$rel"',
            'install -o root -g root -m 0644 "$ROOT/$rel" "$TARGET/$rel"',
            'trap rollback ERR',
            '[[ "$MODE" == "--check" || "$MODE" == "--install" ]]',
        ):
            self.assertIn(fragment,code)
        self.assertNotIn('systemctl restart',code)
        self.assertNotIn('ip route add',code)
        self.assertNotIn('wg set',code)
        self.assertNotIn('nft -f',code)

    def test_mirror_supports_metadata_only_signed_ip_patch(self):
        source=(ROOT/"tools/stage_signed_static_release.py").read_text()
        updater=(ROOT/"updates/live_controller.py").read_text()
        schema='cerato-network-legacy-routed-ui-patch-v1'
        self.assertIn(schema,source)
        self.assertIn(schema,updater)
        self.assertIn('ROUTED_FILES',source)
        self.assertIn('ROUTED_PATCH_FILES',updater)

if __name__=="__main__":
    unittest.main()

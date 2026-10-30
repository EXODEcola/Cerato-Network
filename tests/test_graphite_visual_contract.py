"""Visual design contract and safe updater UI checks.

The user-facing interface should use neutral operational colors and must not
pretend a release is installable when the signed source is unconfigured.
"""
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from patch_live_update_center import UPDATES_JS


class GraphiteContractTests(unittest.TestCase):
    def test_graphite_theme_is_neutral_and_covers_core_console(self):
        css=(ROOT/"themes/cerato-graphite.css").read_text(encoding="utf8")
        self.assertIn("--bg: #0f1114",css)
        self.assertIn("--accent: #78b09f",css)
        self.assertNotIn("#358dde",css.lower())
        self.assertNotIn("linear-gradient(",css.lower())
        for element in (".sidebar",".topbar",".metric",".section",".nav-item",
                        ".table",".cerato-updates",".cerato-update-summary",
                        ".cerato-update-panel",".cerato-update-state"):
            self.assertIn(element,css)

    def test_dev_console_also_uses_same_graphite_operations_theme(self):
        theme=(ROOT/"themes/cerato-graphite.css").read_text(encoding="utf8")
        combined=(ROOT/"web/style.css").read_text(encoding="utf8")
        self.assertIn(theme,combined)
        self.assertTrue(combined.index("CERATO NETWORK — Graphite Operations")>combined.index(":root{"))

    def test_update_screen_has_real_states_and_no_fake_download_action(self):
        for content in ("u.configured","u.installable","reason_code",
                        "source HTTPS", "Ed25519", "id=\"updates-install\"",
                        "id=\"updates-check\"","Dernière vérification"):
            self.assertIn(content,UPDATES_JS)
        self.assertIn("(ready?'':'disabled')",UPDATES_JS)
        self.assertNotIn("Version historique",UPDATES_JS)
        self.assertNotIn("V2",UPDATES_JS)
        self.assertNotIn("Nouvelle génération",UPDATES_JS)


if __name__=="__main__":
    unittest.main()

"""Deterministic Cerato Network dev release numbering without GitHub access."""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from next_dev_release import next_dev_version,DevReleaseError

def tags(*names):
    return [{"tagName":name,"isDraft":False} for name in names]

class DevReleaseTests(unittest.TestCase):
    def test_next_from_current_beta(self):
        self.assertEqual(next_dev_version(tags("v0.1.0-beta.1")),
                         "v0.1.1-dev.1")

    def test_increments_for_each_new_dev_publish(self):
        self.assertEqual(next_dev_version(tags("v0.1.0-beta.1",
                                               "v0.1.1-dev.1",
                                               "v0.1.1-dev.2")),
                         "v0.1.1-dev.3")

    def test_next_patch_after_beta_promotion(self):
        self.assertEqual(next_dev_version(tags("v0.1.0-beta.1",
                                               "v0.1.1-dev.4",
                                               "v0.1.1-beta.1")),
                         "v0.1.2-dev.1")

    def test_stable_anchors_next_patch(self):
        self.assertEqual(next_dev_version(tags("v1.2.5","v1.2.6-dev.3")),
                         "v1.2.6-dev.4")

    def test_no_releases_and_unknown_tags(self):
        self.assertEqual(next_dev_version(tags("other","junk")),"v0.1.0-dev.1")

    def test_ignores_drafts(self):
        self.assertEqual(next_dev_version(tags("v0.1.0-beta.1")+
                            [{"tagName":"v9.0.0","isDraft":True}]),
                         "v0.1.1-dev.1")

    def test_rejects_broken_input(self):
        for obj in (None,{},[{"tagName":17}],["v0.1.0"]):
            with self.assertRaises(DevReleaseError):
                next_dev_version(obj)

if __name__=="__main__":
    unittest.main()

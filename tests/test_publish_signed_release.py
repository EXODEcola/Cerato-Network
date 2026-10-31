"""Local filesystem integration tests of the immutable HTTPS publisher.

Signing and verification are tested separately by the true Ed25519 test suite;
these tests isolate filesystem activation and channel swapping.
"""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import publish_signed_release as publisher

V1="v0.1.0-beta.1"
V2="v0.1.0-beta.2"


def payload(version):
    data={
        "releases/"+version+"/manifest.json":b'{"test":"manifest"}',
        "releases/"+version+"/manifest.sig":b"test-sig",
        "releases/"+version+"/cerato-network-release.zip":b"test-archive",
        "channels/beta.json":json.dumps({"version":version,
                                          "manifest_sha256":"f"*64}).encode(),
        "channels/beta.sig":b"test-channel-sig",
    }
    return data


class SignedPublicPublisherTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)/"cerato-releases"
        self.root.mkdir()
        (self.root/"channels").mkdir()
        (self.root/"releases").mkdir()

    def invoke(self, version=V1, *, apply=False):
        from unittest.mock import patch
        # Exactly the existing signed release validation path is replaced
        # here; verification of real signatures has independent CI tests.
        with patch.object(publisher,"_trusted",return_value=("beta",Path("/tmp/test-only-key"))),\
             patch.object(publisher,"validate",return_value=(version,payload(version))),\
             patch.object(publisher,"_root"),\
             patch.object(publisher,"_existing_channels",
                          side_effect=lambda root: (root/"channels",
                            self._channels_snapshot())),\
             patch.object(publisher.os,"geteuid",return_value=0):
            return publisher.publish(Path("/synthetic/release"),
                Path("/synthetic/channels"),root=self.root,install=apply)

    def _channels_snapshot(self):
        current=self.root/"channels"
        if current.is_symlink():
            current=(self.root/os.readlink(current))
        return {p.name:p.read_bytes() for p in current.iterdir() if p.is_file()}

    def test_check_does_not_touch_public_tree(self):
        report=self.invoke()
        self.assertFalse(report["installed"])
        self.assertFalse((self.root/"releases"/V1).exists())
        self.assertFalse((self.root/".channel-generations").exists())
        self.assertTrue((self.root/"channels").is_dir())

    def test_first_publish_then_atomic_symlink_switch(self):
        done=self.invoke(apply=True)
        self.assertTrue(done["installed"])
        self.assertTrue((self.root/"channels").is_symlink())
        self.assertTrue(os.readlink(self.root/"channels").startswith(".channel-generations/"))
        self.assertEqual((self.root/"channels"/"beta.json").read_bytes(),
                         payload(V1)["channels/beta.json"])
        self.assertTrue((self.root/"releases"/V1/"manifest.json").exists())
        existing=(self.root/"releases"/V1/"manifest.json").read_bytes()
        done2=self.invoke(V2,apply=True)
        self.assertTrue(done2["installed"])
        self.assertEqual((self.root/"channels"/"beta.json").read_bytes(),
                         payload(V2)["channels/beta.json"])
        self.assertEqual((self.root/"releases"/V1/"manifest.json").read_bytes(),existing)
        self.assertTrue((self.root/"releases"/V2/"manifest.json").exists())

    def test_signed_release_never_rolls_channel_back(self):
        self.invoke(V2,apply=True)
        with self.assertRaisesRegex(publisher.PublishError,"Retour arrière"):
            self.invoke(V1,apply=True)
        self.assertFalse((self.root/"releases"/V1).exists())

    def test_release_is_immutable_even_when_channel_points_to_newer(self):
        self.invoke(V1,apply=True)
        existing=self.root/"releases"/V1/"manifest.json"
        existing.write_bytes(b"modified")
        with self.assertRaisesRegex(publisher.PublishError,"Conflit"):
            self.invoke(V1,apply=True)
        self.assertEqual((self.root/"channels"/"beta.json").read_bytes(),
                         payload(V1)["channels/beta.json"])


if __name__=="__main__":
    unittest.main()

"""Offline tests for signed fleet scheduling. Agent must verify signature independently."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "updates"))
from fleet import Fleet, FleetError

class FleetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.fleet=Fleet(root/"data"/"fleet.sqlite")
        self.key=root/"release.key"
        self.pub=root/"release.pub"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.key)],
                       check=True,capture_output=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout","-out",str(self.pub)],
                       check=True,capture_output=True)

    def signed(self, version="v1.2.3"):
        data=json.dumps({"schema":1,"product":"cerato-network","version":version,
                         "artifact":"cerato-network-release.zip","sha256":"a"*64}).encode()
        src=Path(self.tmp.name)/"manifest"
        sig=Path(self.tmp.name)/"signature"
        src.write_bytes(data)
        subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",str(self.key),
                        "-in",str(src),"-out",str(sig)],check=True,capture_output=True)
        return data,sig.read_bytes()

    def test_signed_release_then_queue_and_report(self):
        node=self.fleet.enroll("node-1")
        manifest,sig=self.signed()
        version=self.fleet.stage_verified_release(manifest,sig,self.pub)
        self.assertEqual(self.fleet.schedule(version,ready_gateway_version=version),1)
        work=self.fleet.poll(node["token"])
        self.assertTrue(work["update"])
        self.assertEqual(work["version"],version)
        self.fleet.report(node["token"],version,True)
        self.assertFalse(self.fleet.poll(node["token"])["update"])
        self.assertEqual(self.fleet.overview()[0]["status"],"updated")

    def test_refuse_unsigned_and_failed_gateway(self):
        manifest,sig=self.signed()
        with self.assertRaises(FleetError):
            self.fleet.stage_verified_release(manifest+b"tamper",sig,self.pub)
        version=self.fleet.stage_verified_release(manifest,sig,self.pub)
        with self.assertRaises(FleetError):
            self.fleet.schedule(version,ready_gateway_version="v0.0.0")

    def test_offline_agent_stays_queued(self):
        self.fleet.enroll("node-offline")
        manifest,sig=self.signed()
        version=self.fleet.stage_verified_release(manifest,sig,self.pub)
        self.fleet.schedule(version,ready_gateway_version=version)
        self.assertEqual(self.fleet.overview()[0]["status"],"queued")
        self.assertIsNone(self.fleet.overview()[0]["last_seen"])

    def test_agent_tokens_are_nonrecoverable_and_scoped(self):
        node=self.fleet.enroll("node-2")
        self.assertNotIn("token",self.fleet.overview()[0])
        self.assertNotIn(node["token"],str(self.fleet.overview()))
        with self.assertRaises(FleetError):
            self.fleet.poll("fake")
        with self.assertRaises(FleetError):
            self.fleet.enroll("node-2")

if __name__=="__main__":
    unittest.main()

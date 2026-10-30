"""Safety tests for isolated signed release deployment.

Does not restart services, modify networking or touch /etc.
"""
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from build_release import build
from installer import stage, activate, rollback, StageError


class UpdateInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.source=root/"source"
        self.source.mkdir()
        (self.source/"LICENSE").write_text("MIT",encoding="utf8")
        (self.source/"README.md").write_text("Cerato Network",encoding="utf8")
        (self.source/"gateway.py").write_text("v1",encoding="utf8")
        self.signing=root/"signing.key"
        self.public=root/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.signing)],
                       capture_output=True,check=True)
        os.chmod(self.signing,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.signing),"-pubout","-out",str(self.public)],
                       capture_output=True,check=True)
        self.deploy=root/"isolated-installation"

    def create_release(self,version,content):
        (self.source/"gateway.py").write_text(content,encoding="utf8")
        output=Path(self.tmp.name)/("package-"+version)
        build(self.source,output,version,self.signing)
        return output

    def test_stage_activate_rollback(self):
        a=self.create_release("v0.1.0","release-A")
        info=stage(a,self.public,self.deploy)
        self.assertTrue(info["staged"])
        self.assertFalse(info["already_present"])
        same=stage(a,self.public,self.deploy)
        self.assertTrue(same["already_present"])
        deployed=activate(self.deploy,"v0.1.0",lambda current: (current/"gateway.py").read_text()=="release-A")
        self.assertTrue(deployed["changed"])
        self.assertEqual((self.deploy/"current"/"gateway.py").read_text(),"release-A")

        b=self.create_release("v0.2.0","release-B")
        stage(b,self.public,self.deploy)
        with self.assertRaises(StageError):
            activate(self.deploy,"v0.2.0",lambda current:False)
        self.assertEqual((self.deploy/"current"/"gateway.py").read_text(),"release-A")

        switched=activate(self.deploy,"v0.2.0",lambda current: (current/"gateway.py").read_text()=="release-B")
        self.assertEqual(switched["previous"],"v0.1.0")
        self.assertEqual((self.deploy/"current"/"gateway.py").read_text(),"release-B")
        result=rollback(self.deploy,lambda current: (current/"gateway.py").read_text()=="release-A")
        self.assertEqual(result["version"],"v0.1.0")
        self.assertEqual((self.deploy/"current"/"gateway.py").read_text(),"release-A")

    def test_reject_tampered_release_and_version_collision(self):
        a=self.create_release("v0.1.0","release-A")
        stage(a,self.public,self.deploy)
        (a/"cerato-network-release.zip").write_bytes(b"invalid archive")
        with self.assertRaises(StageError):
            stage(a,self.public,self.deploy)

        other=self.create_release("v0.1.0","different content")
        with self.assertRaises(StageError):
            stage(other,self.public,self.deploy)

    def test_reject_unsafe_deploy_root_and_symlinked_current(self):
        a=self.create_release("v0.1.0","release-A")
        self.deploy.mkdir(mode=0o700)
        self.deploy.chmod(0o755)
        with self.assertRaises(StageError):
            stage(a,self.public,self.deploy)
        self.deploy.chmod(0o700)
        stage(a,self.public,self.deploy)
        (self.deploy/"current").symlink_to(Path(self.tmp.name))
        with self.assertRaises(StageError):
            activate(self.deploy,"v0.1.0",lambda _:True)

    def test_failed_initial_healthcheck_returns_to_uninstalled(self):
        a=self.create_release("v0.1.0","release-A")
        stage(a,self.public,self.deploy)
        with self.assertRaises(StageError):
            activate(self.deploy,"v0.1.0",lambda _:False)
        self.assertFalse((self.deploy/"current").exists())


if __name__=="__main__":
    unittest.main()

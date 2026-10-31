"""Real socket/TLS preproduction integration for Cerato Network.

Unlike mocked distribution unit tests this suite opens genuine loopback sockets:
- a real TLS 1.2+ static HTTPS release server with generated cert,
- a real HTTP health probe for a sandbox "gateway" process,
- signed Ed25519 manifests and archives, OpenSSL verification,
- version staging/activation, rollback on unhealthy candidate,
- two authenticated logical fleet nodes (one intentionally offline).

It NEVER uses the host's WireGuard, nftables, real systemd services or
external IPs. The only production difference patched is the strict
HTTPS-port-443 rule, allowing one ephemeral localhost TLS port *inside this
test process only*; the production client's port validation is unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
for directory in ("tools","updates"):
    sys.path.insert(0,str(ROOT/directory))

from build_release import build
from channel_index import create_channel
from fleet import Fleet
from installer import stage, activate, rollback, StageError
import remote
from remote import DistributionError


def openssl(*args):
    completed=subprocess.run(("openssl",*map(str,args)),
                             capture_output=True,text=True,timeout=20,check=False)
    if completed.returncode:
        raise AssertionError("OpenSSL preproduction command failed: "+completed.stderr[-300:])
    return completed


class QuietFileServer(SimpleHTTPRequestHandler):
    def log_message(self,*args):
        pass


class HealthServer(BaseHTTPRequestHandler):
    """Health endpoint reads an actual switched release tree on each GET."""
    active_root=None

    def do_GET(self):
        if self.path!="/health":
            self.send_error(404)
            return
        path=self.active_root/"current"/"status.json"
        try:
            state=json.loads(path.read_text(encoding="utf8"))
        except (OSError,ValueError):
            state={"healthy":False,"version":None}
        healthy=bool(state.get("healthy") is True)
        payload=json.dumps(state).encode("utf8")
        self.send_response(200 if healthy else 503)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self,*args):
        pass


class LivePreprodTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace=tempfile.TemporaryDirectory(prefix="cerato-live-preprod-")
        cls.root=Path(cls.workspace.name)
        cls.source=cls.root/"source"
        cls.source.mkdir(mode=0o700)
        (cls.source/"README.md").write_text("# Cerato E2E sandbox\n",encoding="utf8")
        (cls.source/"LICENSE").write_text("MIT\n",encoding="utf8")
        cls.signing=cls.root/"signing.key"
        cls.public=cls.root/"signing.pub"
        openssl("genpkey","-algorithm","ED25519","-out",cls.signing)
        os.chmod(cls.signing,0o600)
        openssl("pkey","-in",cls.signing,"-pubout","-out",cls.public)

        # TLS key is separate from the release signing key, like a real
        # HTTPS distributor. Generated cert is only trusted by this test.
        cls.tls_key=cls.root/"tls.key"
        cls.tls_cert=cls.root/"tls.crt"
        openssl("req","-x509","-nodes","-newkey","rsa:2048",
                "-sha256","-days","2","-keyout",cls.tls_key,
                "-out",cls.tls_cert,"-subj","/CN=localhost",
                "-addext","subjectAltName=DNS:localhost,IP:127.0.0.1")
        os.chmod(cls.tls_key,0o600)

        cls.public_tree=cls.root/"public"
        cls.releases={}
        for version,healthy in (("v0.1.0",True),("v0.2.0",True),("v0.3.0",False)):
            (cls.source/"status.json").write_text(
                json.dumps({"version":version,"healthy":healthy}),encoding="utf8")
            output=cls.root/("signed-"+version)
            build(cls.source,output,version,cls.signing)
            cls.releases[version]=output
            advertised=cls.public_tree/"cerato"/"releases"/version
            advertised.mkdir(parents=True,mode=0o700)
            for name in ("manifest.json","manifest.sig","cerato-network-release.zip"):
                shutil.copyfile(output/name,advertised/name)

        channel_dir=cls.public_tree/"cerato"/"channels"
        create_channel(cls.releases["v0.2.0"],"stable",channel_dir,
                       cls.signing,cls.public,validity_seconds=3600)

        cls.https=ThreadingHTTPServer(
            ("127.0.0.1",0),partial(QuietFileServer,directory=str(cls.public_tree)))
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version=ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(str(cls.tls_cert),str(cls.tls_key))
        cls.https.socket=tls.wrap_socket(cls.https.socket,server_side=True)
        cls.https_thread=threading.Thread(target=cls.https.serve_forever,
                                          name="cerato-test-https",daemon=True)
        cls.https_thread.start()
        cls.port=cls.https.server_address[1]
        cls.base=f"https://localhost:{cls.port}/cerato"

        cls.gateway=cls.root/"sandbox-gateway"
        cls.health=ThreadingHTTPServer(("127.0.0.1",0),HealthServer)
        HealthServer.active_root=cls.gateway
        cls.health_thread=threading.Thread(target=cls.health.serve_forever,
                                           name="cerato-test-health",daemon=True)
        cls.health_thread.start()
        cls.health_url=f"http://127.0.0.1:{cls.health.server_address[1]}/health"

    @classmethod
    def tearDownClass(cls):
        for name in ("health","https"):
            server=getattr(cls,name,None)
            if server:
                server.shutdown()
                server.server_close()
        cls.workspace.cleanup()

    def setUp(self):
        # Each test has its own signed release cache / activation tree.
        self.temp=tempfile.TemporaryDirectory(prefix="scenario-",dir=self.root)
        self.addCleanup(self.temp.cleanup)
        self.sandbox=Path(self.temp.name)
        self.gateway=self.sandbox/"gateway"
        HealthServer.active_root=self.gateway
        self.cache=self.sandbox/"verified-cache"
        self.original_base=remote._base

        def local_test_base(url):
            parsed=urllib.parse.urlsplit(url)
            if (parsed.scheme=="https" and parsed.hostname=="localhost" and
                    parsed.port==self.port):
                return url.rstrip("/")+"/"
            return self.original_base(url)

        self.patched=patch.object(remote,"_base",side_effect=local_test_base)
        self.patched.start()
        self.addCleanup(self.patched.stop)
        self.environ=patch.dict(os.environ,{
            "SSL_CERT_FILE":str(self.tls_cert),
            "NO_PROXY":"localhost,127.0.0.1",
            "no_proxy":"localhost,127.0.0.1",
        })
        self.environ.start()
        self.addCleanup(self.environ.stop)

    def health_status(self):
        try:
            with urllib.request.urlopen(self.health_url,timeout=3) as response:
                return response.status,json.loads(response.read())
        except urllib.error.HTTPError as err:
            return err.code,json.loads(err.read())

    def healthcheck(self,current:Path):
        status,result=self.health_status()
        return status==200 and result.get("healthy") is True and (
            current/"status.json").is_file()

    def test_real_https_download_then_activate_and_fleet(self):
        result=remote.check_channel(self.base,"stable",self.public,
                                    installed_version="v0.1.0")
        self.assertTrue(result["update_available"])
        self.assertTrue(result["signed"])

        downloaded=remote.download_channel(self.base,"stable",self.public,self.cache,
                                           installed_version="v0.1.0")
        self.assertTrue(downloaded["downloaded"])
        self.assertEqual(downloaded["version"],"v0.2.0")
        self.assertTrue(Path(downloaded["path"]).is_dir())

        staged=stage(Path(downloaded["path"]),self.public,self.gateway)
        self.assertEqual(staged["version"],"v0.2.0")
        self.assertFalse((self.gateway/"current").exists())
        active=activate(self.gateway,"v0.2.0",self.healthcheck)
        self.assertTrue(active["changed"])
        status,health=self.health_status()
        self.assertEqual(status,200)
        self.assertEqual(health["version"],"v0.2.0")

        # An offline node remains queued; another node fetches and applies
        # its own verified copy. The gateway never runs SSH on those nodes.
        fleet=Fleet(self.sandbox/"fleet"/"state.sqlite")
        online=fleet.enroll("node-online")
        fleet.enroll("node-offline")
        bundle=Path(downloaded["path"])
        version=fleet.stage_verified_release(
            (bundle/"manifest.json").read_bytes(),
            (bundle/"manifest.sig").read_bytes(),self.public)
        count=fleet.schedule(version,ready_gateway_version=health["version"])
        self.assertEqual(count,2)
        task=fleet.poll(online["token"])
        self.assertTrue(task["update"])
        self.assertEqual(task["version"],"v0.2.0")
        node_root=self.sandbox/"online-agent"
        stage(bundle,self.public,node_root)
        node_result=activate(node_root,"v0.2.0",
            lambda path:json.loads((path/"status.json").read_text())["healthy"] is True)
        self.assertTrue(node_result["changed"])
        fleet.report(online["token"],"v0.2.0",True)
        fleet_rows={p["name"]:p for p in fleet.overview()}
        self.assertEqual(fleet_rows["node-online"]["status"],"updated")
        self.assertEqual(fleet_rows["node-offline"]["status"],"queued")
        self.assertIsNone(fleet_rows["node-offline"]["last_seen"])

    def test_real_https_rejects_wrong_tls_trust(self):
        # Without explicitly trusting this ephemeral test certificate, the
        # actual Python HTTPS client must reject the TLS connection.
        with patch.dict(os.environ,{"SSL_CERT_FILE":"/dev/null"}):
            with self.assertRaises(DistributionError):
                remote.check_channel(self.base,"stable",self.public,
                                     installed_version="v0.1.0")

    def test_unhealthy_signed_release_rolls_back_live_health_endpoint(self):
        # Start from a real healthy signed version.
        stage(self.releases["v0.1.0"],self.public,self.gateway)
        activate(self.gateway,"v0.1.0",self.healthcheck)
        self.assertEqual(self.health_status()[1]["version"],"v0.1.0")

        stage(self.releases["v0.3.0"],self.public,self.gateway)
        with self.assertRaises(StageError):
            activate(self.gateway,"v0.3.0",self.healthcheck)
        self.assertEqual(self.health_status()[1]["version"],"v0.1.0")
        self.assertEqual(os.readlink(self.gateway/"current"),"releases/v0.1.0")

    def test_real_https_tampered_archive_is_never_cached(self):
        # In a temporary server tree the file changes on disk while the
        # signed manifest and index remain unchanged.
        asset=(self.public_tree/"cerato"/"releases"/"v0.2.0"/"cerato-network-release.zip")
        original=asset.read_bytes()
        try:
            asset.write_bytes(original+b"tamper")
            with self.assertRaises(DistributionError):
                remote.download_channel(self.base,"stable",self.public,self.cache,
                                        installed_version="v0.1.0")
            self.assertFalse((self.cache/"v0.2.0").exists())
        finally:
            asset.write_bytes(original)


if __name__=="__main__":
    unittest.main()

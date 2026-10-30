"""Hermetic signed HTTPS distribution tests. No external network or services."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"updates"))

from build_release import build
from channel_index import create_channel
from installer import stage
from remote import check_channel, download_channel, DistributionError

BASE="https://releases.example.org/cerato/"


class FakeResponse(io.BytesIO):
    status=200
    def __init__(self,blob,url,*,returned_url=None,declared_size=None):
        super().__init__(blob)
        self.url=url if returned_url is None else returned_url
        self.headers={"Content-Length":str(len(blob) if declared_size is None else declared_size)}
    def geturl(self):
        return self.url


class HTTPFixture:
    def __init__(self,files):
        self.files=dict(files)
        self.redirected=set()
        self.extra_sizes={}

    def __call__(self,request,timeout=None):
        url=request.full_url
        if url not in self.files:
            raise OSError("Remote file missing: "+url)
        return FakeResponse(self.files[url],url,
                            returned_url="https://untrusted.invalid" if url in self.redirected else None,
                            declared_size=self.extra_sizes.get(url))


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.src=root/"source"
        self.src.mkdir()
        (self.src/"README.md").write_text("Cerato Network",encoding="utf8")
        (self.src/"LICENSE").write_text("MIT",encoding="utf8")
        (self.src/"agent.py").write_text("agent-v1",encoding="utf8")
        self.packed=root/"signed-v1"
        self.key=root/"private.key"
        self.pub=root/"trusted.pub"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(self.key)],
                       capture_output=True,check=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout","-out",str(self.pub)],
                       capture_output=True,check=True)
        build(self.src,self.packed,"v1.2.0",self.key)
        self.channels=root/"channels"
        self.now=1800000000
        create_channel(self.packed,"stable",self.channels,self.key,self.pub,
                       issued_at=self.now,validity_seconds=3600)
        self.cache=root/"cache"
        self.destination=root/"isolated-deploy"
        self.transport=self._mock_source()

    def _mock_source(self):
        files={
            BASE+"channels/stable.json":(self.channels/"stable.json").read_bytes(),
            BASE+"channels/stable.sig":(self.channels/"stable.sig").read_bytes(),
        }
        for name in ("manifest.json","manifest.sig","cerato-network-release.zip"):
            files[BASE+"releases/v1.2.0/"+name]=(self.packed/name).read_bytes()
        return HTTPFixture(files)

    def test_discover_download_verify_stage_without_execution(self):
        available=check_channel(BASE,"stable",self.pub,installed_version="v1.1.0",
                                transport=self.transport,now=self.now+30)
        self.assertTrue(available["signed"])
        self.assertTrue(available["update_available"])
        result=download_channel(BASE,"stable",self.pub,self.cache,installed_version="v1.1.0",
                                transport=self.transport,now=self.now+30)
        self.assertTrue(result["downloaded"])
        staged=stage(Path(result["path"]),self.pub,self.destination)
        self.assertEqual(staged["version"],"v1.2.0")
        self.assertFalse((self.destination/"current").exists())
        again=download_channel(BASE,"stable",self.pub,self.cache,installed_version="v1.1.0",
                               transport=self.transport,now=self.now+30)
        self.assertFalse(again["downloaded"])

    def test_older_or_same_release_is_never_downloaded(self):
        self.assertFalse(check_channel(BASE,"stable",self.pub,installed_version="v1.2.0",
                                       transport=self.transport,now=self.now+30)["update_available"])
        with self.assertRaises(DistributionError):
            download_channel(BASE,"stable",self.pub,self.cache,installed_version="v2.0.0",
                             transport=self.transport,now=self.now+30)

    def test_signature_tampering_fails_closed(self):
        url=BASE+"channels/stable.json"
        self.transport.files[url]=self.transport.files[url].replace(b"v1.2.0",b"v9.9.9")
        with self.assertRaises(DistributionError):
            check_channel(BASE,"stable",self.pub,transport=self.transport,now=self.now+30)

    def test_manifest_and_archive_tampering_fails_closed(self):
        url=BASE+"releases/v1.2.0/manifest.json"
        self.transport.files[url]+=b" "
        with self.assertRaises(DistributionError):
            download_channel(BASE,"stable",self.pub,self.cache,transport=self.transport,now=self.now+30)
        self.transport=self._mock_source()
        asset=BASE+"releases/v1.2.0/cerato-network-release.zip"
        self.transport.files[asset]+=b"corruption"
        with self.assertRaises(DistributionError):
            download_channel(BASE,"stable",self.pub,self.cache,transport=self.transport,now=self.now+30)

    def test_reject_redirects_and_oversized_headers(self):
        url=BASE+"channels/stable.json"
        self.transport.redirected.add(url)
        with self.assertRaises(DistributionError):
            check_channel(BASE,"stable",self.pub,transport=self.transport,now=self.now+30)
        self.transport.redirected.clear()
        self.transport.extra_sizes[url]=2_000_000
        with self.assertRaises(DistributionError):
            check_channel(BASE,"stable",self.pub,transport=self.transport,now=self.now+30)

    def test_https_only_and_expiring_signed_indexes(self):
        with self.assertRaises(DistributionError):
            check_channel("http://releases.example.org/cerato/","stable",self.pub,
                          transport=self.transport,now=self.now+30)
        with self.assertRaises(DistributionError):
            check_channel("https://user:password@releases.example.org/cerato/","stable",self.pub,
                          transport=self.transport,now=self.now+30)
        with self.assertRaises(DistributionError):
            check_channel(BASE,"stable",self.pub,transport=self.transport,now=self.now+5000)

    def test_channel_publisher_refuses_rollback(self):
        with self.assertRaises(Exception):
            create_channel(self.packed,"stable",self.channels,self.key,self.pub,
                           issued_at=self.now+60,validity_seconds=3600)

    def test_broken_existing_cache_is_rejected(self):
        cached=self.cache/"v1.2.0"
        cached.mkdir(parents=True)
        (cached/"manifest.json").write_text("bad",encoding="utf8")
        with self.assertRaises(DistributionError):
            download_channel(BASE,"stable",self.pub,self.cache,
                             transport=self.transport,now=self.now+30)


if __name__=="__main__":
    unittest.main()

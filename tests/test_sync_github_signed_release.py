"""A GitHub Release is never trusted until verified against the OVH-pinned key."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import sync_github_signed_release as m


def listing(version="v0.1.0-beta.1"):
    names=(*m.ASSETS,"beta.json","beta.sig","release-verification.pub")
    return json.dumps([{
        "tag_name":version,"draft":False,"prerelease":True,
        "assets":[{"name":a,"browser_download_url":
                   "https://github.com/"+m.REPO+"/releases/download/"+version+"/"+a}
                  for a in names],
    }]).encode()


class GithubMirrorTests(unittest.TestCase):
    def test_finds_exact_assets_on_pinned_repository(self):
        result=m.discover("beta",get=lambda url,max_bytes:listing())
        self.assertEqual(result[0],"v0.1.0-beta.1")
        self.assertIn("manifest.sig",result[1])

    def test_ignores_unsigned_dev_release_and_selects_latest_beta(self):
        data=json.loads(listing("v0.1.1-beta.1"))
        data.insert(0, {
            "tag_name":"v0.1.1-dev.1",
            "draft":False,"prerelease":True,
            "assets":[{"name":"cerato-network-source.tar.gz",
                       "browser_download_url":"https://github.com/"+m.REPO+
                       "/releases/download/v0.1.1-dev.1/cerato-network-source.tar.gz"}],
        })
        data.insert(0,{"tag_name":"not-a-version",
                       "draft":False,"prerelease":True,"assets":[]})
        data.append(json.loads(listing("v0.1.0-beta.1"))[0])
        chosen=m.discover("beta",get=lambda url,limit:json.dumps(data).encode())
        self.assertEqual(chosen[0],"v0.1.1-beta.1")
        self.assertIn("/v0.1.1-beta.1/",chosen[1]["manifest.json"])

    def test_malformed_dev_only_gives_no_beta_release(self):
        data=[
            {"tag_name":"v0.1.1-dev.1","draft":False,
             "prerelease":True,"assets":[]},
            {"tag_name":None,"draft":False,
             "prerelease":True,"assets":[]},
        ]
        self.assertIsNone(m.discover("beta",get=lambda u,n:json.dumps(data).encode()))

    def test_refuses_arbitrary_external_download_url(self):
        data=json.loads(listing())
        data[0]["assets"][0]["browser_download_url"]="https://evil.invalid/manifest.json"
        self.assertIsNone(m.discover("beta",get=lambda url,max_bytes:json.dumps(data).encode()))

    def test_unsigned_github_release_cannot_be_selected(self):
        data=json.loads(listing())
        data[0]["assets"]=[x for x in data[0]["assets"] if x["name"]!="manifest.sig"]
        self.assertIsNone(m.discover("beta",get=lambda url,max_bytes:json.dumps(data).encode()))

    def test_publisher_receives_exact_files_only_after_pinned_key(self):
        with tempfile.TemporaryDirectory() as td:
            pub=Path(td)/"trusted.pub";pub.write_bytes(b"approved public key")
            fetched={
                "manifest.json":b'{"version":"v0.1.0-beta.1"}',
                "manifest.sig":b"signature",
                "cerato-network-release.zip":b"zipdata",
                "beta.json":b"pointer",
                "beta.sig":b"pointer-signature",
                "release-verification.pub":pub.read_bytes(),
            }
            def get(url,limit):
                if url==m.RELEASES_API:return listing()
                return fetched[url.rsplit("/",1)[-1]]
            with patch.object(m,"_trusted",return_value=("beta",pub)),\
                 patch.object(m,"publish",return_value={"installed":False}) as publish:
                result=m.synchronize(get=get)
                self.assertFalse(result["installed"])
                self.assertEqual(result["github_version"],"v0.1.0-beta.1")
                publish.assert_called_once()

    def test_mismatched_public_key_blocks_before_publication(self):
        with tempfile.TemporaryDirectory() as td:
            pub=Path(td)/"trusted.pub";pub.write_bytes(b"original")
            def get(url,limit):
                if url==m.RELEASES_API:return listing()
                return b"attacker"
            with patch.object(m,"_trusted",return_value=("beta",pub)),\
                 patch.object(m,"publish") as publish:
                with self.assertRaisesRegex(m.MirrorError,"différente"):
                    m.synchronize(get=get)
                publish.assert_not_called()


if __name__=="__main__":
    unittest.main()

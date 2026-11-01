"""Redacted real-controller AST review never leaks embedded literals or modifies files."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import review_live_network_generators as review


SAMPLE='''\
PRIVATE_KEY="NOT-FOR-EXPORT-VERY-SENSITIVE"
def render_nft(data):
    x = data["wan_if"]
    text = f'table ip SECRET_FIREWALL {PRIVATE_KEY}'
    return text
def rewrite_wg_peers(data):
    message = "SHOULD-NEVER-BE-EXPORTED"
    return data["peers"]
def apply(data):
    return "AGENT-PRIVATE-TOKEN"
'''


class GeneratorReviewTests(unittest.TestCase):
    def test_scrubs_literals_and_preserves_known_structure(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ceratoctl"
            path.write_text(SAMPLE,encoding="utf-8")
            sha=hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.object(review,"CTL",path):
                data=review.inspect(path,sha)
            report=json.dumps(data)
            self.assertFalse(data["modified"])
            self.assertTrue(data["literal_strings_redacted"])
            self.assertIn("render_nft",report)
            self.assertIn("wan_if",report)
            for secret in ["NOT-FOR-EXPORT","SECRET_FIREWALL",
                           "SHOULD-NEVER-BE-EXPORTED","AGENT-PRIVATE-TOKEN"]:
                self.assertNotIn(secret,report)
            self.assertEqual(path.read_text(),SAMPLE)

    def test_fails_closed_on_hash_change_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ceratoctl"
            path.write_text(SAMPLE)
            with patch.object(review,"CTL",path):
                with self.assertRaises(ValueError):
                    review.inspect(path,"0"*64)
            link=Path(td)/"ceratoctl.link"
            link.symlink_to(path)
            with patch.object(review,"CTL",link):
                with self.assertRaises(ValueError):
                    review.inspect(link,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_fails_closed_if_generator_missing(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ceratoctl"
            path.write_text("def render_nft(data): return 'secret'\n")
            with patch.object(review,"CTL",path):
                with self.assertRaisesRegex(ValueError,"manquantes"):
                    review.inspect(path,hashlib.sha256(path.read_bytes()).hexdigest())


if __name__=="__main__":
    unittest.main()

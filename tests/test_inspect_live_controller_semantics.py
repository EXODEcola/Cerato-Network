"""Verify the live-controller semantic scanner never prints source secrets."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from inspect_live_controller_semantics import examine,profile_node,CONTROLLER,BACKEND
import ast,hashlib


class SafeSemanticAuditTests(unittest.TestCase):
    def test_ast_only_reports_known_metadata(self):
        sensitive="""SECRET='MY-FAKE-PRIVATE-KEY-XYZ'
def render_nft(config, secret=SECRET):
    port = config['public_port']
    key = config['pubkey']
    return f'chain forward {port} blah {secret}'
def rewrite_wg_peers(config):
    return SECRET
def other():
    return SECRET
"""
        tree=ast.parse(sensitive)
        report=profile_node(tree.body[1])
        self.assertEqual(report["function"],"render_nft")
        self.assertIn("public_port",report["config_keys_referenced"])
        self.assertIn("pubkey",report["config_keys_referenced"])
        self.assertNotIn("MY-FAKE",str(report))
        self.assertNotIn("chain forward",str(report))

    def test_refuses_version_mismatch_without_parsing(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ceratoctl"
            path.write_text("def render_nft(config): return 'FAKE-SECRET'\n",encoding="utf-8")
            import inspect_live_controller_semantics as mod
            with patch.object(mod,"CONTROLLER",str(path)):
                report=mod.examine(str(path),"0"*64)
                self.assertEqual(report["blocked"],"source_version_changed")
                self.assertNotIn("FAKE-SECRET",str(report))
                sha=hashlib.sha256(path.read_bytes()).hexdigest()
                good=mod.examine(str(path),sha)
                self.assertEqual(good["functions"][0]["function"],"render_nft")
                self.assertNotIn("FAKE-SECRET",str(good))

    def test_refuses_any_other_file_path(self):
        self.assertEqual(examine("/tmp/private-env-file","f"*64),
                         {"blocked":"untrusted_path"})


if __name__=="__main__":
    unittest.main()

"""Check proxy client-IP handling without opening sockets."""
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"gateway"))
from http_api import Handler


class ProxyIPTests(unittest.TestCase):
    def _remote(self,source,headers,trust):
        dummy=SimpleNamespace(client_address=(source,1234),headers=headers)
        with patch.dict(os.environ,{"CERATO_TRUST_LOCAL_PROXY":trust}):
            return Handler.remote_ip(dummy)

    def test_untrusted_header_ignored_by_default(self):
        self.assertEqual(self._remote("127.0.0.1",{"X-Real-IP":"198.51.100.5"},"0"),"127.0.0.1")

    def test_explicit_loopback_proxy_can_supply_real_ip(self):
        self.assertEqual(self._remote("127.0.0.1",{"X-Real-IP":"198.51.100.5"},"1"),"198.51.100.5")

    def test_public_untrusted_socket_cannot_spoof(self):
        self.assertEqual(self._remote("198.51.100.25",{"X-Real-IP":"198.51.100.5"},"1"),"198.51.100.25")

    def test_forwarded_for_never_accepted(self):
        self.assertEqual(self._remote("127.0.0.1",{"X-Forwarded-For":"198.51.100.7"},"1"),"127.0.0.1")
        self.assertEqual(self._remote("127.0.0.1",{"X-Real-IP":"1.1.1.1, 2.2.2.2"},"1"),"127.0.0.1")


if __name__=="__main__":
    unittest.main()

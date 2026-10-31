"""Unit tests for strict Nginx IP-vhost patching without live side effects."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import install_same_host_releases as helper

IP=helper.HOST
CONFIG=f"""
# fake match: server {{ listen 443 ssl; server_name {IP}; }}
server {{
  listen 80;
  server_name {IP};
  return 301 https://{IP}$request_uri;
}}
server {{
  listen 443 ssl;
  server_name {IP};
  auth_basic "Private panel";
  location / {{
    proxy_pass http://127.0.0.1:8787;
  }}
  location /api/ {{
    auth_basic "Keep API protected";
    proxy_pass http://127.0.0.1:8787;
  }}
}}
"""


class NginxSameHostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"cerato.conf"
        self.path.write_text(CONFIG,encoding="utf8")

    def test_targets_only_explicit_https_ip_vhost(self):
        matches=helper._eligible(self.path.read_text())
        self.assertEqual(len(matches),1)
        with patch.object(helper,"_run",return_value=""):
            plan=helper.preflight(candidates=[self.path],verify_tls=False,trusted_root=Path(self.temp.name))
        self.assertTrue(plan["new"].count(helper.MARKER)==1)
        self.assertIn("auth_basic \"Keep API protected\"",plan["new"])
        self.assertIn("proxy_pass http://127.0.0.1:8787",plan["new"])
        self.assertIn("listen 80;",plan["new"])
        self.assertEqual(self.path.read_text(),CONFIG)

    def test_does_not_guess_default_server_or_duplicate_IP_server(self):
        default=CONFIG.replace(f"server_name {IP};","server_name _;")
        self.assertEqual(helper._eligible(default),[])
        self.path.write_text(CONFIG+"\n"+CONFIG,encoding="utf8")
        with patch.object(helper,"_run",return_value=""):
            with self.assertRaises(helper.ProvisionError):
                helper.preflight(candidates=[self.path],verify_tls=False,trusted_root=Path(self.temp.name))

    def test_idempotence_is_fail_closed(self):
        source=CONFIG.replace("  auth_basic \"Private panel\";",
                              "  "+helper.MARKER+"\n  auth_basic \"Private panel\";")
        self.path.write_text(source,encoding="utf8")
        with patch.object(helper,"_run",return_value=""):
            with self.assertRaises(helper.ProvisionError):
                helper.preflight(candidates=[self.path],verify_tls=False,trusted_root=Path(self.temp.name))

    def test_symlink_resolved_but_edit_inside_etc_only(self):
        other=Path(self.temp.name)/"linked.conf"
        other.symlink_to(self.path)
        with patch.object(helper,"_run",return_value=""):
            with self.assertRaises(helper.ProvisionError):
                # Outside /etc/nginx: no production edit permitted
                helper.preflight(candidates=[other],verify_tls=False)

    def test_tls_failure_refuses_configuration(self):
        with patch.object(helper,"_run",return_value=""),\
             patch.object(helper,"check_tls",side_effect=helper.ProvisionError("invalid TLS")):
            with self.assertRaisesRegex(helper.ProvisionError,"invalid TLS"):
                helper.preflight(candidates=[self.path],verify_tls=True,trusted_root=Path(self.temp.name))
        self.assertEqual(self.path.read_text(),CONFIG)

    def test_nginx_snippet_allows_only_signed_release_files(self):
        snippet=helper.SNIPPET.read_text(encoding="utf8")
        for required in ("limit_except GET HEAD","auth_basic off;",
                         "try_files $uri =404;","root /srv/cerato-releases/public;"):
            self.assertIn(required,snippet)
        self.assertNotIn("autoindex on",snippet)
        self.assertNotIn("proxy_pass ",snippet)

    def test_cert_validation_uses_standard_trust_store(self):
        import inspect
        source=inspect.getsource(helper.check_tls)
        self.assertIn("ssl.create_default_context()",source)
        self.assertIn("server_hostname=host",source)
        self.assertNotIn("CERT_NONE",source)

if __name__=="__main__":
    unittest.main()

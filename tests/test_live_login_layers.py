"""Login-layer audit reads structure only and never reveals Nginx config."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'integrations'))
from inspect_live_login_layers import nginx_layer,inspect_layers


class LiveLoginLayersTests(unittest.TestCase):
    def test_nginx_basic_is_detected_but_username_and_path_never_output(self):
        command=[sys.executable,'-c','''print("""
server {
  auth_basic "Secret admin gateway";
  auth_basic_user_file /private/secret/.htpasswd;
}
""")''']
        data=nginx_layer(command)
        self.assertEqual(data['inspection'],'structural')
        self.assertTrue(data['http_basic_declared'])
        self.assertTrue(data['credential_file_directive_declared'])
        self.assertFalse(data['effective_route_protection_verified'])
        output=json.dumps(data)
        self.assertNotIn('Secret admin gateway',output)
        self.assertNotIn('/private/secret',output)

    def test_nginx_error_is_unknown_not_unprotected(self):
        out=nginx_layer([sys.executable,'-c','import sys; print("secret",file=sys.stderr);sys.exit(1)'])
        self.assertIsNone(out['http_basic_declared'])
        self.assertNotIn('secret',json.dumps(out))

    def test_legacy_routes_are_detected_without_emitting_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            server=Path(root)/'server.py'
            client=Path(root)/'app.js'
            server.write_text('''
USERNAME="hidden-account"
PASSWORD="never-expose-this"
class Handler:
    def check_session(self): return False
    def read_body(self): return {}
    def do_GET(self):
        if self.path=="/api/status": return None
    def do_POST(self):
        if self.path=="/api/login": return None
        if self.path=="/api/logout": return None
''',encoding='utf8')
            client.write_text('const prompt = "Mot de passe administrateur";',encoding='utf8')
            report=inspect_layers(server,client)
            self.assertTrue(report['legacy_password_endpoint'])
            self.assertTrue(report['legacy_login_ui'])
            self.assertFalse(report['new_account_routes_live'])
            self.assertFalse(report['new_mfa_routes_live'])
            self.assertFalse(report['safe_to_disable_existing_auth'])
            self.assertNotIn('hidden-account',json.dumps(report))
            self.assertNotIn('never-expose-this',json.dumps(report))
            self.assertFalse(report['network_changes'])


if __name__=='__main__':
    unittest.main()

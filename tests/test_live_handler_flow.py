"""Structural-only handler map tests (no real server source or secrets)."""
from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integrations'))
from inspect_live_handler_flow import audit


class HandlerMapTests(unittest.TestCase):
    def test_only_known_route_metadata_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend = root / 'server.py'
            frontend = root / 'app.js'
            backend.write_text('''
SECRET = "do-not-export"
SERVER_IP = "198.51.100.22"
def read_body(): return {}
class Server:
    def check_session(self, write=False): return True
    def send_json(self, *args): pass
    def do_GET(self):
        p = self.path
        if p == '/api/status':
            if not self.check_session(): return
            return self.send_json(200, {})
    def do_POST(self):
        p = self.path
        if not self.check_session(write=True): return
        if p == '/api/nat/add':
            request = self.read_body()
            return self.send_json(200, request)
''', encoding='utf8')
            frontend.write_text("const navigation=['overview','machines'];", encoding='utf8')
            report = audit(backend, frontend)
            self.assertEqual(report['format'], 'cerato-live-handler-map-v1')
            self.assertEqual(report['candidate_count'], 1)
            self.assertEqual(report['handler_candidates'][0]['conditional_routes']['GET'],
                             ['/api/status'])
            self.assertEqual(report['handler_candidates'][0]['conditional_routes']['POST'],
                             ['/api/nat/add'])
            self.assertFalse(report['network_changes'])
            packed = json.dumps(report)
            self.assertNotIn('do-not-export', packed)
            self.assertNotIn('198.51.100.22', packed)
            self.assertNotIn('SECRET', packed)

    def test_read_only_no_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend = root / 'server.py'
            frontend = root / 'app.js'
            backend.write_text('''
class Handler:
    def do_GET(self):
        if self.path == '/api/status': return self.send_json(200,{})
    def do_POST(self): return self.send_json(200,{})
    def check_session(self): return True
    def read_body(self): return {}
    def send_json(self,*args): return None
''', encoding='utf8')
            frontend.write_text("'overview';", encoding='utf8')
            before = (backend.read_bytes(), frontend.read_bytes())
            audit(backend, frontend)
            self.assertEqual(before, (backend.read_bytes(), frontend.read_bytes()))


if __name__ == '__main__':
    unittest.main()

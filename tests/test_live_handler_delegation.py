"""Recognize delegated POST routing while never exporting unreviewed constants."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'integrations'))
from inspect_live_handler_flow import audit


class DelegatedHandlerTests(unittest.TestCase):
    def test_delegated_post_routes_through_class_and_global_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            server=root/'server.py'
            app=root/'app.js'
            server.write_text('''
SECRET="private-secret-never-export"
def nested_post(server):
    if server.path == '/api/nat/add':
        return server.send_json(200,{})
    if server.path == '/api/ip/configure':
        return server.send_json(200,{})
    if server.path == '/api/INTERNAL-SECRET':
        return server.send_json(200,{})
class Backend:
    def do_GET(self):
        if self.path == '/api/status': return self.send_json(200,{})
    def do_POST(self):
        return self.route_post()
    def route_post(self):
        if not self.check_session(write=True): return
        return nested_post(self)
    def check_session(self,write=False): return True
    def read_body(self): return {}
    def send_json(self,*args): return None
''',encoding='utf8')
            app.write_text("'overview';'ips';'nat';",encoding='utf8')
            report=audit(server,app)
            handler=report['handler_candidates'][0]
            self.assertEqual(handler['direct_conditional_routes']['POST'],[])
            self.assertEqual(handler['conditional_routes']['POST'],
                             ['/api/ip/configure','/api/nat/add'])
            self.assertGreaterEqual(handler['reachable_delegate_counts']['POST'],2)
            self.assertEqual(handler['reachable_call_counts']['POST']['check_session'],1)
            packed=json.dumps(report)
            self.assertNotIn('private-secret-never-export',packed)
            self.assertNotIn('/api/INTERNAL-SECRET',packed)
            self.assertFalse(report['network_changes'])

    def test_recursive_helper_does_not_loop_forever(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            server=root/'server.py'
            app=root/'app.js'
            server.write_text('''
class Backend:
    def do_GET(self): return self.send_json(200,{})
    def do_POST(self): return self.route_post()
    def route_post(self): return self.route_post()
    def check_session(self): return True
    def read_body(self): return {}
    def send_json(self,*args): return None
''',encoding='utf8')
            app.write_text("'overview';",encoding='utf8')
            result=audit(server,app)
            self.assertEqual(result['candidate_count'],1)
            self.assertEqual(result['handler_candidates'][0]['reachable_delegate_counts']['POST'],1)


if __name__ == '__main__':
    unittest.main()

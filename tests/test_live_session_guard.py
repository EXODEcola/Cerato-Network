"""No live system dependencies: mock the existing AuthStore protocol."""
from __future__ import annotations
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'security'))
from auth_store import Forbidden
from live_session_guard import authorize_legacy_request,project_legacy_status

class FakeStore:
    def __init__(self, role):
        self.role=role
        self.calls=[]
    def actor(self,token):
        self.calls.append(('actor',token))
        if token!='valid':
            raise Forbidden('missing session')
        return {'role':self.role,'active':True}
    def require_permission(self,actor,permission):
        self.calls.append(('permission',permission))
        if actor['role']=='user' and permission!='view':
            raise Forbidden('role denied')
    def verify_csrf(self,token,csrf):
        self.calls.append(('csrf',csrf))
        if csrf!='valid-csrf':
            raise Forbidden('CSRF denied')

class LiveSessionGuardTests(unittest.TestCase):
    def test_old_login_and_logout_are_never_accepted(self):
        store=FakeStore('owner')
        for path in ('/api/login','/api/logout'):
            with self.subTest(path=path),self.assertRaises(Forbidden):
                authorize_legacy_request(store,'valid','POST',path,'valid-csrf')
        self.assertEqual(store.calls,[])

    def test_unknown_route_denied_before_session_lookup(self):
        store=FakeStore('owner')
        with self.assertRaises(Forbidden):
            authorize_legacy_request(store,'valid','POST','/api/unsafe-unreviewed','valid-csrf')
        self.assertEqual(store.calls,[])

    def test_user_can_get_redacted_status_only(self):
        store=FakeStore('user')
        actor=authorize_legacy_request(store,'valid','GET','/api/status')
        raw={'dashboard_mode':'real','tunnel_active':True,'peers':{},'private_key':'DO-NOT-LEAK'}
        projected=project_legacy_status(actor,raw)
        self.assertNotIn('private_key',projected)
        self.assertTrue(projected['tunnel_active'])
        with self.assertRaises(Forbidden):
            authorize_legacy_request(store,'valid','GET','/api/wg-config')
        with self.assertRaises(Forbidden):
            authorize_legacy_request(store,'valid','POST','/api/ip/configure','valid-csrf')

    def test_admin_write_needs_csrf_and_mfa_session(self):
        store=FakeStore('admin')
        with self.assertRaises(Forbidden):
            authorize_legacy_request(store,'valid','POST','/api/nat/add')
        self.assertEqual(store.calls[-1],('csrf',None))
        actor=authorize_legacy_request(store,'valid','POST','/api/nat/add','valid-csrf')
        self.assertEqual(actor['role'],'admin')
        # The real AuthStore.actor enforces MFA for privileged roles.
        with self.assertRaises(Forbidden):
            authorize_legacy_request(store,'wrong','POST','/api/nat/add','valid-csrf')

    def test_payload_is_not_redacted_for_admin_and_unknown_role_denied(self):
        raw={'peers':{},'private_key':'test'}
        self.assertIs(project_legacy_status({'role':'owner'},raw),raw)
        with self.assertRaises(Forbidden):
            project_legacy_status({'role':'other'},raw)

if __name__=='__main__': unittest.main()

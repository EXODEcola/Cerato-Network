"""Mock-backed contract tests for the isolated legacy Auth API bridge.

No privileged network commands or production state are touched.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'security'))
from auth_store import Forbidden, InvalidCredentials
from legacy_auth_api import LegacyAuthAPI

ORIGIN = 'https://network.example.org'


class Store:
    def __init__(self, role='owner'):
        self.role = role
        self.calls = []

    def is_initialized(self):
        return True

    def setup_owner(self, token, email, password):
        if token != 'temporary':
            raise InvalidCredentials('bad')
        return {'role': 'owner', 'email': email}

    def login(self, email, password, ip):
        self.calls.append(('login', email, ip))
        if password != 'valid':
            raise InvalidCredentials('bad')
        if self.role == 'owner':
            return {'mfa_required': True, 'mfa_setup': True,
                    'challenge': 'challenge', 'otp_uri': 'otpauth://example'}
        return {'session': 'secret-token', 'csrf': 'csrf-secret',
                'account': {'role': 'user'}}

    def complete_mfa(self, challenge, code):
        if code != '123456':
            raise InvalidCredentials('bad code')
        return {'session': 'secret-token', 'csrf': 'csrf-secret',
                'account': {'role': 'owner'}, 'recovery_codes': ['one', 'two']}

    def actor(self, token):
        if token != 'valid-session':
            raise InvalidCredentials('expired')
        return {'role': self.role, 'id': 10}

    def verify_csrf(self, token, csrf):
        if csrf != 'valid-csrf':
            raise Forbidden('csrf')

    def rotate_csrf(self, token):
        return 'new-csrf'

    def require_permission(self, actor, permission):
        if actor['role'] == 'user':
            raise Forbidden('read-only')

    def list_accounts(self, actor):
        return [{'role': 'owner'}]

    def create_account(self, actor, email, password, role):
        return {'role': role, 'email': email}

    def manage_account(self, actor, target_id, **kwargs):
        if target_id == 1:
            raise Forbidden('owner immutable')
        return {'id': target_id}

    def delete_account(self, actor, target_id):
        if target_id == 1:
            raise Forbidden('owner immutable')

    def logout(self, token):
        self.calls.append(('logout', token))

    def change_own_identity(self, actor, password, **fields):
        return {'id': actor['id']}


class LegacyAuthAPITests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.api = LegacyAuthAPI(self.store, allowed_origin=ORIGIN)

    def call(self, method, path, **kwargs):
        return self.api.handle(method, path, origin=ORIGIN, **kwargs)

    def test_public_status_and_one_time_owner_setup(self):
        self.assertEqual(self.call('GET', '/api/auth/setup-status').payload,
                         {'initialized': True})
        response = self.call('POST', '/api/auth/setup',
                             body={'token': 'temporary', 'email': 'a@example.com',
                                   'password': 'long-private-password'})
        self.assertEqual(response.code, 201)
        self.assertIsNone(response.cookie)
        self.assertEqual(self.call('POST', '/api/auth/setup',
                         body={'token': 'bad'}).code, 401)

    def test_cross_site_mutations_are_blocked_before_login(self):
        for origin in (None, 'https://evil.example.org', 'http://network.example.org'):
            response = self.api.handle('POST', '/api/auth/login', origin=origin,
                                       body={'email': 'a', 'password': 'valid'})
            self.assertEqual(response.code, 403)
        self.assertEqual(self.store.calls, [])

    def test_password_only_does_not_create_owner_session(self):
        response = self.call('POST', '/api/auth/login',
                             body={'email': 'x', 'password': 'valid'},
                             source_ip='192.0.2.2')
        self.assertIsNone(response.cookie)
        self.assertEqual(response.payload['challenge'], 'challenge')

    def test_mfa_completion_issues_secure_cookie(self):
        response = self.call('POST', '/api/auth/mfa/verify',
                             body={'challenge': 'challenge', 'code': '123456'})
        self.assertEqual(response.code, 200)
        self.assertEqual(response.payload['recovery_codes'], ['one', 'two'])
        self.assertNotIn('session', response.payload)
        for attr in ('HttpOnly', 'Secure', 'SameSite=Strict'):
            self.assertIn(attr, response.cookie)

    def test_user_login_does_not_require_mfa(self):
        self.store.role = 'user'
        response = self.call('POST', '/api/auth/login',
                             body={'email': 'x', 'password': 'valid'})
        self.assertEqual(response.payload['csrf'], 'csrf-secret')
        self.assertIn('cerato_session=', response.cookie)

    def test_old_session_routes_retired(self):
        for route in ('/api/login', '/api/logout'):
            self.assertEqual(self.call('POST', route, body={}).code, 410)
        self.assertEqual(self.store.calls, [])

    def test_old_network_routes_are_not_intercepted(self):
        for path in ('/api/ip/configure', '/api/nat/add', '/api/status',
                     '/api/updates/install', '/api/peers'):
            self.assertIsNone(self.call('POST', path))

    def test_profile_csrf_and_logout(self):
        response = self.call('GET', '/api/auth/me', session='valid-session')
        self.assertEqual(response.payload['csrf'], 'new-csrf')
        self.assertEqual(self.call('POST', '/api/auth/logout', body={},
                                   session='valid-session').code, 403)
        result = self.call('POST', '/api/auth/logout', body={},
                           session='valid-session', csrf='valid-csrf')
        self.assertEqual(result.code, 200)
        self.assertIn('Max-Age=0', result.cookie)

    def test_user_cannot_manage_accounts(self):
        self.store.role = 'user'
        self.assertEqual(self.call('GET', '/api/accounts',
                                   session='valid-session').code, 403)
        self.assertEqual(self.call('POST', '/api/accounts', body={'role': 'admin'},
                         session='valid-session', csrf='valid-csrf').code, 403)

    def test_mutation_payloads_are_explicitly_allowlisted(self):
        for extra in (
            {'email': 'u@example.net', 'password': 'valid-password-123',
             'role': 'user', 'owner': True},
            {'email': 'u@example.net', 'password': 'valid-password-123',
             'role': 'user', 'network_admin': True},
        ):
            response=self.call('POST','/api/accounts',body=extra,
                               session='valid-session',csrf='valid-csrf')
            self.assertEqual(response.code,403)
        result=self.call('PATCH','/api/accounts/23',
                         body={'active':False,'owner':True},
                         session='valid-session',csrf='valid-csrf')
        self.assertEqual(result.code,403)
        self.assertEqual(self.call('PATCH','/api/accounts/23',body={},
                                  session='valid-session',csrf='valid-csrf').code,403)
        self.assertEqual(self.call('PATCH','/api/auth/me',
                                  body={'current_password':'pw','role':'owner'},
                                  session='valid-session',csrf='valid-csrf').code,403)
        self.assertEqual(self.call('PATCH','/api/accounts/23',
                                  body={'reset_mfa':True},
                                  session='valid-session',csrf='valid-csrf').code,200)

    def test_admin_can_manage_others_not_owner(self):
        self.store.role = 'admin'
        def request(verb, target):
            return self.call(verb, '/api/accounts/' + str(target),
                             body={'active': False}, session='valid-session',
                             csrf='valid-csrf').code
        self.assertEqual(request('PATCH', 23), 200)
        self.assertEqual(request('PATCH', 1), 403)
        self.assertEqual(request('DELETE', 1), 403)
        self.assertEqual(request('DELETE', 23), 200)

    def test_unreviewed_account_methods_are_denied(self):
        self.assertEqual(self.call('PUT', '/api/accounts/7').code, 405)
        self.assertEqual(self.call('GET', '/api/accounts/7',
                                   session='valid-session').code, 405)
        self.assertEqual(self.call('POST', '/api/accounts/7', body={},
                                  session='valid-session', csrf='valid-csrf').code, 405)

    def test_only_approved_https_origin_is_valid(self):
        for origin in ('http://network.example.org',
                       'https://network.example.org/path',
                       'https://user:password@network.example.org'):
            with self.assertRaises(ValueError):
                LegacyAuthAPI(self.store, allowed_origin=origin)


if __name__ == '__main__':
    unittest.main()

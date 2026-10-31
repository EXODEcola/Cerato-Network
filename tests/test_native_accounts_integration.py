"""Owner/Admin/User management smoke tests using a real private AuthStore.

Not bound to any socket and never deployed on the historical RISE-1 backend.
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from auth_store import AuthStore,InvalidCredentials,Forbidden
from legacy_auth_api import LegacyAuthAPI
from mfa import code_for_counter

ORIGIN="https://cerato.example.test"


class NativeAccountsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.store=AuthStore(Path(self.folder.name)/"private/accounts.db")
        self.store.setup_owner(self.store.issue_bootstrap_token(),
                               "owner@example.test","owner-password-secure-123")
        self.api=LegacyAuthAPI(self.store,allowed_origin=ORIGIN)

    def login(self,email,password):
        result=self.store.login(email,password,"192.0.2.31")
        if result.get("mfa_required"):
            self.assertNotIn("session",result)
            self.assertTrue(result["mfa_setup"])
            code=code_for_counter(result["otp_secret"],int(time.time())//30)
            result=self.store.complete_mfa(result["challenge"],code)
        return result

    def request(self,method,path,session,body=None):
        return self.api.handle(method,path,session=session["session"],
                               csrf=session["csrf"],origin=ORIGIN,body=body)

    def test_owner_can_manage_accounts_without_touching_owner_or_creating_second(self):
        owner=self.login("owner@example.test","owner-password-secure-123")
        create=self.request("POST","/api/accounts",owner,{
            "email":"admin@example.test","password":"admin-password-secure-123",
            "role":"admin"})
        self.assertEqual(create.code,201)
        self.assertEqual(create.payload["account"]["role"],"admin")
        admin_id=create.payload["account"]["id"]
        self.assertEqual(self.request("GET","/api/accounts",owner).code,200)
        self.assertEqual(self.request("PATCH","/api/accounts/1",owner,{"active":False}).code,403)
        self.assertEqual(self.request("DELETE","/api/accounts/1",owner,{}).code,403)
        self.assertEqual(self.request("POST","/api/accounts",owner,{
            "email":"bad@example.test","password":"password-good-123","role":"owner"}).code,403)
        self.assertEqual(self.request("PATCH",f"/api/accounts/{admin_id}",owner,
                                      {"role":"user"}).code,200)

    def test_deactivate_and_reset_mfa_revoke_privileged_sessions(self):
        owner=self.login("owner@example.test","owner-password-secure-123")
        admin=self.request("POST","/api/accounts",owner,{
            "email":"admin@example.test","password":"admin-password-secure-123",
            "role":"admin"}).payload["account"]
        first=self.login("admin@example.test","admin-password-secure-123")
        self.assertEqual(self.store.actor(first["session"])["role"],"admin")
        modified=self.request("PATCH",f"/api/accounts/{admin['id']}",owner,
                              {"reset_mfa":True})
        self.assertEqual(modified.code,200)
        with self.assertRaises(InvalidCredentials):
            self.store.actor(first["session"])
        renewed=self.login("admin@example.test","admin-password-secure-123")
        self.assertEqual(self.store.actor(renewed["session"])["role"],"admin")
        self.assertEqual(self.request("PATCH",f"/api/accounts/{admin['id']}",owner,
                                      {"active":False}).code,200)
        with self.assertRaises(InvalidCredentials):
            self.store.actor(renewed["session"])

    def test_user_cannot_see_account_registry_or_change_firewall(self):
        owner=self.login("owner@example.test","owner-password-secure-123")
        self.request("POST","/api/accounts",owner,{
            "email":"viewer@example.test","password":"viewer-password-secure-123",
            "role":"user"})
        user=self.login("viewer@example.test","viewer-password-secure-123")
        self.assertEqual(self.request("GET","/api/accounts",user).code,403)
        self.assertEqual(self.request("POST","/api/accounts",user,{
            "email":"bad@example.test","password":"pw-goodlong-123","role":"admin"}).code,403)
        with self.assertRaises(Forbidden):
            self.store.require_permission(self.store.actor(user["session"]),"network_write")

    def test_owner_profile_change_revokes_session_and_needs_current_password(self):
        owner=self.login("owner@example.test","owner-password-secure-123")
        denied=self.request("PATCH","/api/auth/me",owner,{
            "current_password":"incorrect-password",
            "email":"new@example.test"})
        self.assertEqual(denied.code,401)
        success=self.request("PATCH","/api/auth/me",owner,{
            "current_password":"owner-password-secure-123",
            "email":"new@example.test"})
        self.assertEqual(success.code,200)
        self.assertTrue(success.payload["reauth_required"])
        with self.assertRaises(InvalidCredentials):
            self.store.actor(owner["session"])
        second=self.store.login("new@example.test","owner-password-secure-123","192.0.2.31")
        self.assertTrue(second.get("mfa_required"))


if __name__=="__main__":
    unittest.main()

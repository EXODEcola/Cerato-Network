"""Staged Cerato Network account UI: role management, MFA, safe forms.

These tests never connect to the live OVH panel or activate legacy auth.
"""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
JS=ROOT/"web/live-auth-overlay.js"
CSS=ROOT/"web/live-auth-overlay.css"

class NativeAccountManagementUITests(unittest.TestCase):
    def test_javascript_syntax(self):
        run=subprocess.run(["node","--check",str(JS)],capture_output=True,text=True,timeout=12)
        self.assertEqual(run.returncode,0,run.stderr)

    def test_admin_and_owner_may_manage_nonowner_accounts(self):
        src=JS.read_text(encoding="utf8")
        for expected in (
            "function editAccount(acc)", "function myProfile()",
            "acc.role==='owner'", "acc.id===state.account.id",
            "state.account.role==='user'",
            "roleSelect.value!==acc.role",
            "changes.new_password=password.input.value",
            "await call('/api/accounts/'+acc.id,'PATCH',changes)",
            "await call('/api/accounts/'+acc.id,'PATCH',{reset_mfa:true})",
            "await call('/api/accounts/'+acc.id,'PATCH',{active:!acc.active})",
        ):
            self.assertIn(expected,src)

    def test_profile_requires_password_and_reauthentication(self):
        src=JS.read_text(encoding="utf8")
        self.assertIn("current_password:current.input.value",src)
        self.assertIn("await call(endpoint+'me','PATCH',data)",src)
        self.assertIn("state.account=null;state.csrf='';",src)
        self.assertIn("location.reload();",src)
        self.assertIn("if(!data.current_password || Object.keys(data).length===1)",src)

    def test_browser_may_not_store_sessions_or_bypass_server_policy(self):
        src=JS.read_text(encoding="utf8")
        for prohibited in ("localStorage","sessionStorage","eval(","new Function(","document.cookie",
                           "innerHTML","outerHTML", "Authorization: Basic", "credentials:'include'"):
            self.assertNotIn(prohibited,src)
        self.assertIn("credentials:'same-origin'",src)
        self.assertIn("headers['X-Cerato-CSRF']=state.csrf",src)
        self.assertIn("errorMessage(panel,err)",src)
        self.assertIn("confirm('Révoquer la 2FA",src)

    def test_graphite_styles_exist(self):
        src=CSS.read_text(encoding="utf8")
        self.assertIn(".cerato-account-status",src)
        self.assertIn(".cerato-account-row-actions",src)
        self.assertIn("@media (max-width: 500px)",src)


if __name__=="__main__":
    unittest.main()

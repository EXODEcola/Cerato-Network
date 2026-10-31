"""RBAC migration tests for existing RISE-1 endpoints (no live server)."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"security"))
from legacy_policy import allow,privilege,audit_gaps
from auth_store import Forbidden

OWNER={"role":"owner","active":True}
ADMIN={"role":"admin","active":True}
VIEWER={"role":"user","active":True}


class LegacyPolicyTests(unittest.TestCase):
    def test_accounts_and_network_mutations_denied_to_read_only_user(self):
        mutations=[
            "/api/peers","/api/peers/remove","/api/ip/add","/api/ip/remove",
            "/api/ip/configure","/api/ip/preview","/api/nat/add",
            "/api/nat/remove","/api/updates/check","/api/updates/install",
        ]
        for route in mutations:
            with self.subTest(route=route):
                with self.assertRaises(Forbidden):
                    allow("POST",route,VIEWER)
                self.assertEqual(allow("POST",route,ADMIN),"network_write")
        for role in (OWNER,ADMIN):
            self.assertEqual(allow("GET","/api/accounts",role),"accounts_manage")
        with self.assertRaises(Forbidden):
            allow("GET","/api/accounts",VIEWER)

    def test_viewer_only_uses_redacted_status_route(self):
        self.assertEqual(allow("GET","/api/status",VIEWER),"view")
        self.assertEqual(allow("GET","/api/auth/me",VIEWER),"view")
        self.assertEqual(allow("PATCH","/api/auth/me",VIEWER),"view")
        for route in ("/api/peers","/api/nat","/api/ip","/api/wg-config",
                      "/api/events","/api/updates"):
            with self.subTest(route=route):
                with self.assertRaises(Forbidden):
                    allow("GET",route,VIEWER)

    def test_unknown_routes_and_roles_fail_closed(self):
        for method,path in (
            ("POST","/api/arbitrary-root-command"),
            ("GET","/api/private-key"),
            ("POST","/api/ip/configure-superuser"),
            ("POST","/api/updates/start/any"),
        ):
            with self.assertRaises(Forbidden):
                privilege(method,path)
        with self.assertRaises(Forbidden):
            allow("GET","/api/status",None)
        with self.assertRaises(Forbidden):
            allow("GET","/api/status",{"role":"support"})
        with self.assertRaises(Forbidden):
            allow("GET","/api/status",{"role":"admin","active":False})

    def test_route_inventory_surfaces_gaps_before_cutover(self):
        actual=[
            "/api/status","/api/updates/check",
            "/api/ip/configure","/api/unknown-legacy-admin",
        ]
        self.assertEqual(audit_gaps(actual),["/api/unknown-legacy-admin"])


if __name__=="__main__":
    unittest.main()

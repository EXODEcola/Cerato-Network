"""Offline assertions for the RISE-1 read-only persistent /32 dependency audit."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from audit_routed_cutover_dependencies import audit, peer_public_allowed


PUBLIC="54.37.165.151"
VPN="10.77.0.2"
WAN="enp1s0f0"
WG="wg-cerato"
DUMMY="SYNTHETIC-PEER-KEY"


class Reads:
    def __init__(self, alias=True, allowed=False, restore="enabled", rules="enabled"):
        self.alias=alias
        self.allowed=allowed
        self.restore=restore
        self.rules=rules

    def __call__(self,args):
        if args==["ip","-j","-4","address","show","dev",WAN]:
            return json.dumps([{"addr_info":[{"family":"inet","local":PUBLIC}] if self.alias else []}])
        if args==["wg","show",WG,"allowed-ips"]:
            return DUMMY+"\t"+VPN+"/32"+(" "+PUBLIC+"/32" if self.allowed else "")+"\n"
        if args==["systemctl","is-enabled","cerato-network-additional-ip.service"]:
            return self.restore
        if args==["systemctl","is-enabled","cerato-network-rules.service"]:
            return self.rules
        return None


class GatewayAuditTests(unittest.TestCase):
    def make(self,alias=True,managed=True,maps=1,allowed=False,rules="enabled"):
        ctx=tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        location=Path(ctx.name)
        config=location/"config.json"
        state=location/"additional-ip-managed.json"
        config.write_text(json.dumps({"pool":[PUBLIC], "mappings":[
            {"public_ip": PUBLIC, "public_port":8080} for _ in range(maps)]
        }),encoding="utf-8")
        state.write_text(json.dumps({"local_ipv4":[
            {"ip":PUBLIC,"wan":WAN,"preexisting":True}] if managed else []}
        ),encoding="utf-8")
        return audit(PUBLIC,VPN,WAN,WG,read=Reads(alias=alias,allowed=allowed,
                                                rules=rules),config=config,managed=state)

    def test_real_like_gateway_detects_three_independent_reapply_hazards(self):
        r=self.make()
        self.assertFalse(r["can_activate"])
        self.assertFalse(r["modified"])
        self.assertEqual(r["findings"]["public_ip_still_local_on_wan"],"yes")
        self.assertEqual(r["findings"]["public_ip_managed_for_recreate_on_boot"],"yes")
        self.assertEqual(r["findings"]["per_port_nat_mappings_for_public_ip"],1)
        self.assertEqual(r["findings"]["wg_peer_allows_public_32"],"no")
        self.assertIn("rules_regenerator_must_support_routed_mode",r["blockers"])
        self.assertNotIn(DUMMY,str(r))

    def test_no_conflicts_still_do_not_authorize_apply(self):
        r=self.make(alias=False,managed=False,maps=0,allowed=True,rules="disabled")
        self.assertEqual(r["blockers"],[])
        self.assertFalse(r["can_activate"])

    def test_missing_files_are_unknown_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)
            r=audit(PUBLIC,VPN,WAN,WG,read=Reads(),config=path/"missing.json",
                    managed=path/"missing-state.json")
        self.assertFalse(r["can_activate"])
        self.assertIn("cerato_config_or_pool_needs_review",r["blockers"])
        self.assertIn("persistent_alias_restore_needs_migration",r["blockers"])
        self.assertIn("nat_mappings_require_atomic_conversion",r["blockers"])

    def test_wg_key_is_never_reported(self):
        result=peer_public_allowed(Reads(allowed=True),WG,VPN,PUBLIC)
        self.assertTrue(result)
        report=self.make(allowed=True)
        self.assertNotIn(DUMMY,json.dumps(report))

    def test_interface_injection_rejected(self):
        with self.assertRaises(ValueError):
            audit(PUBLIC,VPN,WAN+";",WG,read=Reads())


if __name__=="__main__":
    unittest.main()

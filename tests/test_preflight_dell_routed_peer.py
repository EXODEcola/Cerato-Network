"""Non-invasive Dell peer readiness audit tests, no shell or privileged commands."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from preflight_dell_routed_peer import check,AuditError

VPN="10.77.0.2"
PUBLIC="54.37.165.151"
TUNNEL="wg-cerato"
SSHD="""permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
"""

def fake_read(args):
    values={
        ("ip","-j","-4","address","show","dev",TUNNEL):json.dumps([{
            "addr_info":[{"family":"inet","local":VPN}]}]),
        ("ip","-4","rule","show"): "0: from all lookup local\n1100: from 10.77.0.2 lookup 51820\n32766: from all lookup main\n",
        ("ip","-4","route","show","table","51820"):"default dev wg-cerato scope link\n",
        ("ip","-j","-4","route","get","1.1.1.1","from",VPN):
            '[{"dst":"1.1.1.1","dev":"wg-cerato","src":"10.77.0.2"}]',
        ("sysctl","-n","net.ipv4.conf.all.rp_filter"):"2\n",
        ("sysctl","-n","net.ipv4.conf.wg-cerato.rp_filter"):"2\n",
        ("/usr/sbin/sshd","-T"):SSHD,
        ("ufw","status"):"Status: inactive\n",
        ("ss","-H","-ltn"):"LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
                            "LISTEN 0 4096 127.0.0.1:3306 0.0.0.0:*\n",
        ("ip","link","show","dev","tailscale0"):"7: tailscale0: <POINTOPOINT,UP> mtu 1280\n",
    }
    result=values.get(tuple(args))
    if result is None:
        raise AuditError("Unlisted read")
    return result


def run(readfn=fake_read,**overrides):
    kwargs={"public_ip":PUBLIC,"vpn_ip":VPN,"tunnel":TUNNEL,
            "table":51820,"priority":1101}
    kwargs.update(overrides)
    return check(readfn,**kwargs)


class DellPreflightTests(unittest.TestCase):
    def test_confirmed_existing_dell_baseline_never_claims_live_routing(self):
        result=run()
        self.assertEqual(result["checks"]["wg_interface_has_vpn_ip"],"pass")
        self.assertEqual(result["checks"]["vpn_source_returns_via_wg"],"pass")
        self.assertEqual(result["checks"]["ssh_global_publickey_only"],"pass")
        self.assertEqual(result["checks"]["target_priority_available"],"pass")
        self.assertEqual(result["ufw_state"],"inactive")
        self.assertEqual(result["listening_tcp_ports"],[22,3306])
        self.assertFalse(result["ready_to_activate"])
        self.assertFalse(result["host_public_firewall_reviewed"])
        self.assertFalse(result["rollback_armed"])
        self.assertFalse(result["modified"])
        self.assertNotIn("pubkey",json.dumps(result))

    def test_collision_detected_before_any_rule_is_created(self):
        def read(args):
            if args==["ip","-4","rule","show"]:
                return "1101: from 10.77.0.3 lookup 51820\n"
            return fake_read(args)
        self.assertEqual(run(read)["checks"]["target_priority_available"],"block")

    def test_fail_closed_when_source_route_unavailable(self):
        def read(args):
            if args==["ip","-j","-4","route","get","1.1.1.1","from",VPN]:
                raise AuditError("unavailable")
            return fake_read(args)
        out=run(read)
        self.assertEqual(out["checks"]["vpn_source_returns_via_wg"],"unknown")
        self.assertIn("vpn_source_returns_via_wg",out["remaining_observed_issues"])

    def test_public_ip_already_attached_blocks_staging(self):
        def read(args):
            if args==["ip","-j","-4","address","show","dev",TUNNEL]:
                return json.dumps([{"addr_info":[
                    {"family":"inet","local":VPN},
                    {"family":"inet","local":PUBLIC}]}])
            return fake_read(args)
        self.assertEqual(run(read)["checks"]["public_ip_not_yet_on_wg"],"block")

    def test_insecure_ssh_or_strict_rp_filter_never_pass(self):
        def read(args):
            if args==["/usr/sbin/sshd","-T"]:
                return SSHD.replace("passwordauthentication no","passwordauthentication yes")
            if args==["sysctl","-n","net.ipv4.conf.all.rp_filter"]:
                return "1\n"
            if args==["sysctl","-n","net.ipv4.conf.wg-cerato.rp_filter"]:
                return "0\n"
            return fake_read(args)
        result=run(read)
        self.assertEqual(result["checks"]["ssh_global_publickey_only"],"block")
        self.assertEqual(result["checks"]["rp_filter_non_strict"],"block")

    def test_invalid_targets_fail_closed(self):
        for overrides in ({"public_ip":VPN},{"vpn_ip":PUBLIC},
                          {"tunnel":"wg0;rm -rf /"},{"priority":10},
                          {"table":254}):
            with self.subTest(overrides=overrides),self.assertRaises(AuditError):
                run(**overrides)


if __name__=="__main__":
    unittest.main()

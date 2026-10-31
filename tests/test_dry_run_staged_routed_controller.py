"""RISE-1 nft renderer dry run with synthetic controller, no network changes."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import dry_run_staged_routed_controller as runner
import stage_live_routed_controller as staging

SOURCE="""from __future__ import annotations
import ipaddress
def render_nft(data):
    wan,wg=(data['wan_if'],data['wg_if'])
    entries=['table ip cerato_network {',' chain prerouting {',
             'type nat hook prerouting priority dstnat; policy accept;']
    for m in sorted(data['mappings'],key=lambda x:(x['public_ip'],x['proto'],x['public_port'])):
        peer=data['peers'][m['peer']]
        entries.append(f'iifname "{wan}" ip daddr {m["public_ip"]} {m["proto"]} dport {m["public_port"]} dnat to {peer["ip"]}:{m["target_port"]}')
    entries.extend([' }',' chain postrouting {',
                    'type nat hook postrouting priority srcnat; policy accept;',
                    ' }',' chain forward {',
                    'type filter hook forward priority -30; policy accept;',
                    f'iifname "{wan}" oifname "{wg}" ct status dnat accept',
                    f'iifname "{wan}" oifname "{wg}" drop',
                    f'iifname "{wg}" oifname "{wan}" ct state established,related accept',
                    f'iifname "{wg}" oifname "{wan}" drop',
                    ' }',' chain input {',
                    'type filter hook input priority -30; policy accept;'])
    if data['pool']:
        csv=', '.join(sorted(data['pool'], key=lambda x:ipaddress.ip_address(x)))
        entries.append(f'iifname "{wan}" ip daddr {csv} drop')
    entries.append(' }')
    entries.append('}')
    return '\\n'.join(entries)+'\\n'
def rewrite_wg_peers(data):
    original=data["old_wg"]
    temp=data["output_sink"]
    temp.write_text(original)
"""

DATA={
    "wan_if":"enp1s0f0","wg_if":"wg-cerato",
    "pool":["54.37.165.151"],
    "peers":{"dell-r530":{"ip":"10.77.0.2","pubkey":"EXAMPLE-KEY-ONLY"}},
    "mappings":[{"public_ip":"54.37.165.151","proto":"tcp","public_port":8080,
                 "target_port":8080,"peer":"dell-r530"}]
}
STATE={"schema":1,"local_ipv4":[{"ip":"54.37.165.151","wan":"enp1s0f0",
                                  "preexisting":True}]}


class RoutedDryRunTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix="cerato-safe-nft-",dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.source=self.root/"ceratoctl"
        self.source.write_text(SOURCE,encoding="utf8")
        self.staged=self.root/"patched"
        self.staged.mkdir(mode=0o700)
        self.staged.joinpath("ceratoctl").write_bytes(staging.transform(self.source.read_bytes()))
        self.config=self.root/"config.json"
        self.config.write_text(json.dumps(DATA))
        self.managed=self.root/"additional-ip-managed.json"
        self.managed.write_text(json.dumps(STATE))
        helper_hashes={}
        for filename in runner.APPROVED_SUPPORT:
            content=(ROOT/"network"/(
                "live_routed_compat.py" if filename=="cerato_routed_support.py"
                else filename)).read_bytes()
            (self.staged/filename).write_bytes(content)
            helper_hashes[filename]=hashlib.sha256(content).hexdigest()
        self.hashes=(hashlib.sha256(self.source.read_bytes()).hexdigest(),
                     hashlib.sha256((self.staged/"ceratoctl").read_bytes()).hexdigest(),
                     helper_hashes)

    def simulate(self):
        origin_sha,patched_sha,helpers=self.hashes
        with patch.object(runner,"APPROVED_SOURCE_SHA",origin_sha),patch.object(
                runner,"APPROVED_PATCHED_SHA",patched_sha),patch.object(
                runner,"APPROVED_SUPPORT",helpers):
            return runner.simulate(
                self.staged,"54.37.165.151","10.77.0.2","51.210.223.57",
                controller=self.source,config=self.config,state=self.managed)

    def test_routed_simulation_keeps_old_render_and_changes_nothing(self):
        before=(self.source.read_bytes(),self.config.read_bytes(),
                self.managed.read_bytes(),(self.staged/"ceratoctl").read_bytes())
        report=self.simulate()
        self.assertEqual(report["status"],"validated-in-memory")
        self.assertTrue(report["current_legacy_render_unchanged"])
        self.assertTrue(report["virtual_forward_inbound"])
        self.assertTrue(report["virtual_forward_outbound"])
        self.assertTrue(report["virtual_gateway_input_drop_preserved"])
        self.assertEqual(report["virtual_nat_mappings_removed"],1)
        self.assertFalse(report["ready_for_routed_ip"])
        self.assertFalse(report["network_modified"])
        self.assertFalse(report["configuration_files_modified"])
        self.assertFalse((self.staged/"__pycache__").exists())
        self.assertNotIn("EXAMPLE-KEY",json.dumps(report))
        after=(self.source.read_bytes(),self.config.read_bytes(),
               self.managed.read_bytes(),(self.staged/"ceratoctl").read_bytes())
        self.assertEqual(before,after)

    def test_tampered_helper_rejected(self):
        bad=self.staged/"routed_firewall.py"
        bad.write_bytes(bad.read_bytes()+b"\n# changed")
        with self.assertRaisesRegex(runner.SimulationError,"Empreinte"):
            self.simulate()

    def test_mismatched_controller_rejected(self):
        self.source.write_text(SOURCE+"\n# changed")
        with self.assertRaisesRegex(runner.SimulationError,"Empreinte"):
            self.simulate()

    def test_bad_current_live_mappings_refused(self):
        corrupt={**DATA,"mappings":[]}
        self.config.write_text(json.dumps(corrupt))
        with self.assertRaisesRegex(runner.SimulationError,"publication"):
            self.simulate()

    def test_missing_local_state_refused(self):
        self.managed.write_text(json.dumps({"schema":1,"local_ipv4":[]}))
        with self.assertRaisesRegex(runner.SimulationError,"persistant"):
            self.simulate()

    def test_invalid_peer_refused(self):
        self.config.write_text(json.dumps({**DATA,"peers":{}}))
        with self.assertRaisesRegex(runner.SimulationError,"Pair VPN"):
            self.simulate()


if __name__=="__main__":
    unittest.main()

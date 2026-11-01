"""Regression guards for the staged production cutover. No host commands executed."""
from __future__ import annotations
from unittest import TestCase
from unittest.mock import patch
from pathlib import Path
import importlib.util
import sys

PATH=Path(__file__).resolve().parents[1]/"scripts"/"managed_routed_cutover.py"
spec=importlib.util.spec_from_file_location("managed_routed_cutover",PATH)
installer=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=installer
spec.loader.exec_module(installer)

PUB="54.37.165.151"
WAN="enp1s0f0"

class ManagedCutoverTests(TestCase):
    def test_peer_firewall_only_allows_ssh_and_established_to_public_via_wg(self):
        raw=installer.fw_script()
        self.assertIn('iifname "wg-cerato" ip daddr '+PUB+' tcp dport 22 accept',raw)
        self.assertIn('iifname "wg-cerato" ip daddr '+PUB+' drop',raw)
        self.assertLess(raw.index("tcp dport 22 accept"),raw.index(PUB+" drop"))
        self.assertNotIn("flush ruleset",raw)
        self.assertNotIn("tailscale0",raw)
        self.assertNotIn("192.168.",raw)

    def test_gateway_only_moves_exact_additional_ip_without_affecting_others(self):
        config={
            "wan_if":"enp1s0f0","wg_if":"wg-cerato","pool":[PUB,"54.37.165.160"],
            "peers":{"dell":{"ip":"10.77.0.2","pubkey":"synthetic"}},
            "mappings":[
                {"public_ip":PUB,"proto":"tcp","public_port":8080,
                 "target_port":8080,"peer":"dell"},
                {"public_ip":"54.37.165.160","proto":"tcp","public_port":8443,
                 "target_port":443,"peer":"dell"}],
        }
        managed={"schema":1,"local_ipv4":[
            {"ip":PUB,"wan":WAN,"preexisting":True},
            {"ip":"54.37.165.160","wan":WAN,"preexisting":True}
        ],"routed_ipv4":[]}
        def reader(path):
            if path==installer.CFG:return config
            if path==installer.STATE:return managed
            raise AssertionError("Unrecognized file")
        with patch.object(installer,"json_read",side_effect=reader):
            result_cfg,result_state=installer.planned_configs("dell")
        self.assertEqual(result_cfg["routed_ipv4"],[{"ip":PUB,"peer":"dell"}])
        self.assertEqual(result_state["routed_ipv4"],
                         [{"ip":PUB,"peer":"dell","wan":WAN}])
        self.assertEqual(len(result_cfg["mappings"]),1)
        self.assertEqual(result_cfg["mappings"][0]["public_ip"],"54.37.165.160")
        self.assertEqual(len(result_state["local_ipv4"]),1)
        self.assertEqual(len(config["mappings"]),2)
        self.assertEqual(len(managed["local_ipv4"]),2)
        self.assertNotIn("management_ipv4",config)
        self.assertEqual(result_cfg["management_ipv4"],installer.ADMIN)

    def test_invalid_duplicate_local_record_fails_closed(self):
        managed={"local_ipv4":[{"ip":PUB},{"ip":PUB}],"routed_ipv4":[]}
        cfg={"mappings":[{"public_ip":PUB}]}
        with patch.object(installer,"json_read",side_effect=lambda p:cfg if p==installer.CFG else managed):
            with self.assertRaises(installer.CutoverError):
                installer.planned_configs("dell")

    def test_two_separate_persistent_rollback_deadlines(self):
        self.assertGreater(installer.DEADLINE_PEER,installer.DEADLINE_GATEWAY)
        self.assertGreaterEqual(installer.DEADLINE_GATEWAY,20)

    def test_preparation_references_source_helper_not_installed_alias(self):
        self.assertEqual(installer.INPUT_SUPPORT, (
            "live_routed_compat.py","routed_nft_inject.py","routed_firewall.py"))
        self.assertEqual(installer.EXPECTED_SUPPORT, (
            "cerato_routed_support.py","routed_nft_inject.py","routed_firewall.py"))
        source=PATH.read_text()
        self.assertIn('for item in (*INPUT_SUPPORT,"stage_live_routed_controller.py"):',source)
        self.assertIn('for filename in EXPECTED_SUPPORT:',source)

    def test_source_controller_pinned_to_live_observed_sha(self):
        self.assertEqual(installer.SOURCE_SHA,
            "41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6")
        self.assertEqual(installer.ADMIN,"51.210.223.57")
        self.assertEqual(installer.VPN,"10.77.0.2")
        self.assertEqual(installer.RULE_PRIORITY,1101)

    def test_recover_orphan_refuses_active_state_before_any_change(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            p=Path(d)
            (p/"state.json").write_text('{"phase":"armed"}')
            with patch.object(installer,"BASE",p), patch.object(installer,"command") as cmd:
                with self.assertRaises(installer.CutoverError):
                    installer.recover_orphan_preparation("gateway")
                cmd.assert_not_called()
            self.assertTrue(p.exists())

    def test_recover_orphan_refuses_unknown_file_without_network_mutation(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            p=Path(d)
            (p/"unexpected").write_text("keep me")
            with patch.object(installer,"BASE",p), patch.object(installer,"command") as cmd:
                with self.assertRaises(installer.CutoverError):
                    installer.recover_orphan_preparation("gateway")
                cmd.assert_not_called()
            self.assertTrue((p/"unexpected").is_file())

    def test_recover_orphan_archives_only_unchanged_gateway(self):
        from tempfile import TemporaryDirectory
        from types import SimpleNamespace
        with TemporaryDirectory() as d:
            p=Path(d)/"original"
            p.mkdir()
            (p/"config.before").write_text("known config")
            live=Path(d)/"current"
            live.write_text("known config")
            shell_units=Path(d)/"systemd"
            shell_units.mkdir()
            def cmd(*args,**kwargs):
                if args[:3]==("systemctl","is-active","--quiet"):
                    return SimpleNamespace(returncode=3)
                if args[:5]==("nft","list","chain","ip","cerato_network"):
                    return ('table ip cerato_network { chain prerouting { '
                            'ip daddr 54.37.165.151 tcp dport 8080 '
                            'dnat to 10.77.0.2:8080 } }')
                raise AssertionError(args)
            original_path=installer.Path
            def remap(arg):
                if str(arg)=="/etc/systemd/system":return shell_units
                return original_path(arg)
            with patch.object(installer,"BASE",p),\
                 patch.object(installer,"Path",side_effect=remap),\
                 patch.object(installer,"gateway_preflight"),\
                 patch.object(installer,"wg_peer",return_value=(
                     "dell",{"pubkey":"synthetic"})),\
                 patch.object(installer,"wg_allowed",return_value=["10.77.0.2/32"]),\
                 patch.object(installer,"CONTROLLER",Path(d)/"controller"),\
                 patch.object(installer,"CFG",live),\
                 patch.object(installer,"STATE",Path(d)/"managed"),\
                 patch.object(installer,"EXPECTED_SUPPORT",()),\
                 patch.object(installer,"command",side_effect=cmd):
                result=installer.recover_orphan_preparation("gateway")
            self.assertEqual(result["status"],"orphan_archived")
            self.assertFalse(p.exists())
            self.assertTrue(original_path(result["archive"]).is_dir())
            self.assertFalse(result["network_modified"])

    def test_reset_refuses_non_restored_and_never_executes_mutation(self):
        with patch.object(installer,"read_state",return_value={
                "role":"peer","version":1,"phase":"armed"}):
            with patch.object(installer,"command") as shell:
                with self.assertRaises(installer.CutoverError):
                    installer.reset_restored("peer")
                shell.assert_not_called()

    def test_reset_rejects_active_watchdog_or_routing_rule(self):
        def command(*args,**kw):
            if args[:3]==("systemctl","is-active","--quiet"):
                return type("R",(),{"returncode":1})()
            if args[:3]==("systemctl","is-enabled","--quiet"):
                return type("R",(),{"returncode":1})()
            if args[:3]==("ip","-4","rule"):
                return "1101: from 54.37.165.151 lookup 51820\n"
            raise AssertionError("Unexpected read: "+str(args))
        with patch.object(installer,"read_state",return_value={
                "role":"peer","version":1,"phase":"restored"}):
            with patch.object(installer,"command",side_effect=command):
                with patch.object(installer,"address_exists",return_value=False):
                    with self.assertRaises(installer.CutoverError):
                        installer.reset_restored("peer")

    def test_reset_archives_only_after_complete_rollback(self):
        from tempfile import TemporaryDirectory
        from types import SimpleNamespace
        from unittest.mock import patch
        with TemporaryDirectory() as folder:
            root=Path(folder)
            base=root/"cutover"
            base.mkdir()
            (base/"state.json").write_text('{"phase":"restored"}')
            units=root/"systemd"
            units.mkdir()
            (units/"cerato-routed-rollback-peer.timer").write_text("timer")
            (units/"cerato-routed-rollback-peer.service").write_text("service")
            def mock_command(*args,**kw):
                if args[0]=="systemctl" and args[1]=="daemon-reload":return ""
                if args[0]=="systemctl":return SimpleNamespace(returncode=1)
                if args[:4]==("ip","-4","rule","show"):
                    return "0: from all lookup local\n"
                if args[:4]==("nft","list","table","ip"):
                    return SimpleNamespace(returncode=1)
                raise AssertionError(args)
            original_path=installer.Path
            def remap(arg):
                if str(arg)=="/etc/systemd/system":return units
                return original_path(arg)
            with patch.object(installer,"BASE",base),\
                 patch.object(installer,"Path",side_effect=remap),\
                 patch.object(installer,"command",side_effect=mock_command),\
                 patch.object(installer,"read_state",return_value={
                     "role":"peer","version":1,"phase":"restored"}),\
                 patch.object(installer,"address_exists",return_value=False):
                result=installer.reset_restored("peer")
            self.assertEqual(result["status"],"reset_to_prepared_state")
            self.assertFalse(base.exists())
            self.assertTrue(original_path(result["archived_state"]).is_dir())
            self.assertFalse((units/"cerato-routed-rollback-peer.timer").exists())

    def test_no_automatic_live_change_on_import(self):
        self.assertTrue(callable(installer.prepare))
        self.assertTrue(callable(installer.activate))
        self.assertTrue(callable(installer.rollback))
        self.assertTrue(callable(installer.persist))

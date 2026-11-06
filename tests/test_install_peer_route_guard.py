"""Tests of the optional Dell-only periodic route guard without system calls."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"install_peer_route_guard.py"
spec=importlib.util.spec_from_file_location("cerato_guard",SCRIPT)
guard=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=guard
spec.loader.exec_module(guard)

class RouteGuardTests(unittest.TestCase):
    def test_preflight_accepts_only_committed_peer_and_correct_source_route(self):
        data=json.dumps({"phase":"committed","role":"peer","version":1}).encode()
        def files(path,*,max_size):
            return data if path==guard.STATE else b"#!/usr/bin/env python3\n"
        def command(*args):
            if args[:2]==("systemctl","is-enabled"):return "enabled"
            if args[:2]==("systemctl","is-active"):return "active"
            if args[:4]==("ip","-4","rule","show"):
                return "1101: from 54.37.165.151 lookup 51820"
            if args[:4]==("ip","-4","route","show"):
                return "default dev wg-cerato scope link"
            if args[:4]==("ip","-4","addr","show"):
                return "inet 54.37.165.151/32 scope global wg-cerato"
            if args[:4]==("ip","-j","-4","route"):
                return '[{"dev":"wg-cerato"}]'
            raise AssertionError(args)
        with patch.object(guard.os,"geteuid",return_value=0),\
             patch.object(guard,"_is_regular_owned",side_effect=files),\
             patch.object(guard,"_cmd",side_effect=command):
            state=guard._preflight()
            self.assertTrue(state["route_source_ok"])
            self.assertEqual(state["network_modified"],False)

    def test_rejects_missing_policy_route(self):
        with patch.object(guard.os,"geteuid",return_value=0),\
             patch.object(guard,"_is_regular_owned",return_value=json.dumps({
                 "phase":"committed","role":"peer","version":1}).encode()),\
             patch.object(guard,"_cmd",side_effect=lambda *a: (
               "enabled" if a[1]=="is-enabled" else
               "active" if a[1]=="is-active" else ""
             )):
            with self.assertRaisesRegex(guard.GuardError,"1101"):
                guard._preflight()

    def test_check_is_read_only_and_does_not_create_units(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            with patch.object(guard,"UNITS",folder), \
                 patch.object(guard,"_preflight",return_value={"route_source_ok":True}),\
                 patch.object(guard,"_cmd") as cmd:
                report=guard.check()
            self.assertFalse(report["service_unit_installed"])
            self.assertFalse(report["timer_unit_installed"])
            self.assertEqual(list(folder.iterdir()),[])
            cmd.assert_not_called()

    def test_install_then_repeat_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            commands=[]
            def command(*args):
                commands.append(args)
                if args[:2]==("systemctl","is-active"):return "active"
                return ""
            with patch.object(guard,"UNITS",folder), \
                 patch.object(guard,"_preflight",return_value={"route_source_ok":True}),\
                 patch.object(guard,"_cmd",side_effect=command):
                first=guard.install()
                second=guard.install()
            self.assertTrue(first["timer_active"])
            self.assertTrue(second["timer_active"])
            self.assertEqual((folder/guard.SERVICE).read_text(),guard.SERVICE_TEXT)
            self.assertEqual((folder/guard.TIMER).read_text(),guard.TIMER_TEXT)
            self.assertIn(("systemctl","enable","--now",guard.TIMER),commands)
            self.assertNotIn(("ip","rule","add"),commands)
            self.assertNotIn(("nft","-f"),commands)

    def test_existing_foreign_systemd_file_refused_without_command(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            (folder/guard.SERVICE).write_text("foreign unit\n")
            with patch.object(guard,"UNITS",folder), \
                 patch.object(guard,"_preflight",return_value={"route_source_ok":True}),\
                 patch.object(guard,"_cmd") as cmd:
                with self.assertRaisesRegex(guard.GuardError,"étrangère"):
                    guard.install()
                cmd.assert_not_called()
            self.assertEqual((folder/guard.SERVICE).read_text(),"foreign unit\n")

    def test_partial_unit_creation_rolls_back_only_own_files(self):
        with tempfile.TemporaryDirectory() as folder:
            folder=Path(folder)
            commands=[]
            def command(*args):
                commands.append(args)
                if args[:3]==("systemctl","enable","--now"):
                    raise guard.GuardError("simulated startup failure")
                return ""
            with patch.object(guard,"UNITS",folder), \
                 patch.object(guard,"_preflight",return_value={"route_source_ok":True}),\
                 patch.object(guard,"_cmd",side_effect=command),\
                 patch.object(guard.subprocess,"run") as shell:
                with self.assertRaises(guard.GuardError):
                    guard.install()
                self.assertEqual(list(folder.iterdir()),[])
                self.assertTrue(shell.called)

if __name__=="__main__":
    unittest.main()

"""Protect the live Cerato network controller hotfix from unguarded edits.

No real Cerato services or network commands are executed by these tests.
"""
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "repair_live_ceratoctl_shebang.py"
spec = importlib.util.spec_from_file_location("cerato_shebang_repair", SCRIPT)
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


class ShebangRepairTests(unittest.TestCase):
    def test_known_approved_live_payload_is_pinned(self):
        self.assertEqual(repair.BROKEN_SHA256,
                         "4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793")
        self.assertEqual(repair.SHEBANG, b"#!/usr/bin/env python3\n")

    def test_unrecognized_payload_is_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "ceratoctl"
            p.write_text('print("unexpected")\n')
            p.chmod(0o755)
            sha_before = hashlib.sha256(p.read_bytes()).hexdigest()
            original_inspect=repair.inspect
            def test_inspect(path=repair.CONTROLLER):
                # The test runner is not root; production always checks root ownership.
                if path.is_symlink() or not path.is_file():
                    raise repair.RepairError("untrusted file")
                raw=path.read_bytes()
                compile(raw,str(path),"exec")
                return ({"missing_shebang":not raw.startswith(b"#!"),
                         "known_broken_version":repair.sha256(raw)==repair.BROKEN_SHA256,
                         "known_repaired_version":False},raw)
            with patch.object(repair,"inspect",side_effect=test_inspect),patch.object(
                    repair.os,"geteuid",return_value=0),patch.object(repair,"run_status") as status:
                with self.assertRaises(repair.RepairError):
                    repair.repair(path=p,backups=Path(directory)/"backups")
                status.assert_not_called()
            self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),sha_before)

    def test_known_payload_is_backed_up_and_directly_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            p=base/"ceratoctl"
            p.write_bytes(b'import json\nprint(json.dumps({"ok": True}))\n')
            p.chmod(0o755)
            content=p.read_bytes()
            with patch.object(repair,"BROKEN_SHA256",repair.sha256(content)), patch.object(
                    repair.os,"geteuid",return_value=0):
                # Only skip the Linux root ownership check in CI.
                original_inspect=repair.inspect
                def inspect_test(path=repair.CONTROLLER):
                    raw=path.read_bytes()
                    compile(raw,str(path),"exec")
                    return ({"known_broken_version":repair.sha256(raw)==repair.BROKEN_SHA256,
                             "known_repaired_version":raw.startswith(repair.SHEBANG) and
                               repair.sha256(raw[len(repair.SHEBANG):])==repair.BROKEN_SHA256,
                             "missing_shebang":not raw.startswith(b"#!")},raw)
                with patch.object(repair,"inspect",side_effect=inspect_test):
                    result=repair.repair(path=p,backups=base/"backups")
                    self.assertEqual(result["status"],"repaired")
                    self.assertEqual(result["network_modified"],False)
                    self.assertEqual(p.read_bytes(),repair.SHEBANG+content)
                    self.assertEqual(Path(result["backup"]).read_bytes(),content)
                    second=repair.repair(path=p,backups=base/"backups")
                    self.assertEqual(second["status"],"already_repaired")

    def test_staging_controller_keeps_shebang(self):
        sys_path = str(ROOT/"scripts")
        import sys
        if sys_path not in sys.path:
            sys.path.insert(0,sys_path)
        from stage_live_routed_controller import transform
        original = (b'def render_nft(data):\n    return "anything"\n'
                    b'def rewrite_wg_peers(data):\n'
                    b'    original="key"\n'
                    b'    temp=data["temp"]\n'
                    b'    temp.write_text(original)\n')
        transformed = transform(original)
        self.assertTrue(transformed.startswith(repair.SHEBANG))
        compile(transformed,"<test>","exec")


if __name__=="__main__":
    unittest.main()

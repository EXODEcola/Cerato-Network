"""The sole new sudo privilege is the immutable read-only IPv4 status command."""
from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import authorize_live_ipctl_status as m


class ScopedIpctlAuthorizationTests(unittest.TestCase):
    def test_sudoers_exact_command_only(self):
        text=m.RULE_BYTES.decode("utf8")
        self.assertEqual(
            text.splitlines()[-1],
            "ceratonet ALL=(root) NOPASSWD: /usr/local/sbin/cerato-ipctl status",
        )
        for word in ("ALL=(ALL)", "SETENV", "import-local", "preview",
                     "route", "nat-add", "visudo -f", "NOPASSWD: ALL"):
            self.assertNotIn(word, text)
        self.assertTrue(str(m.CLI).startswith("/usr/local/sbin/"))

    def test_web_probe_uses_identical_nopasswd_call(self):
        data={"managed":[{"mode":"routed-wg"}],"pool":["example"]}
        calls=[]
        def fake_call(*args, **kw):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout=json.dumps(data))
        with patch.object(m,"call",side_effect=fake_call):
            self.assertTrue(m.web_probe())
        self.assertEqual(calls,[(m.RUNUSER,"-u","ceratonet","--",
                                 m.SUDO,"-n",str(m.CLI),"status")])

    def test_preflight_disallows_alternate_existing_rule(self):
        with tempfile.TemporaryDirectory() as d:
            rule=Path(d)/"other"
            rule.write_text("ceratonet ALL=(root) NOPASSWD: ALL\n")
            with patch.object(m,"RULE",rule),patch.object(m.os,"geteuid",return_value=0):
                with self.assertRaisesRegex(m.ScopedSudoError,"différente"):
                    m.preflight()

    def test_install_is_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            rule=Path(d)/"cerato-ipctl-status"
            state={"routed_count":1,"web_status_access":False,
                   "rule_present":False,"network_modified":False}
            with patch.object(m,"RULE",rule), \
                 patch.object(m,"preflight",return_value=state), \
                 patch.object(m,"web_probe",return_value=True), \
                 patch.object(m.shutil,"which",return_value="/usr/sbin/visudo"), \
                 patch.object(m,"call",return_value=SimpleNamespace(returncode=0)):
                output=m.install()
                self.assertEqual(output["status"],"authorized")
                self.assertEqual(rule.read_bytes(),m.RULE_BYTES)
                self.assertEqual(rule.stat().st_mode & 0o777,0o440)
                self.assertFalse(output["network_modified"])
                self.assertFalse(output["service_restarted"])
                state["rule_present"]=True
                self.assertEqual(m.install()["status"],"already_authorized")

    def test_failed_web_probe_rolls_back_only_new_rule(self):
        with tempfile.TemporaryDirectory() as d:
            rule=Path(d)/"cerato-ipctl-status"
            with patch.object(m,"RULE",rule), \
                 patch.object(m,"preflight",return_value={"routed_count":1}), \
                 patch.object(m,"web_probe",return_value=False), \
                 patch.object(m.shutil,"which",return_value="/usr/sbin/visudo"), \
                 patch.object(m,"call",return_value=SimpleNamespace(returncode=0)):
                with self.assertRaisesRegex(m.ScopedSudoError,"Contrôle sudo"):
                    m.install()
            self.assertFalse(rule.exists())

    def test_existing_status_output_not_exposed(self):
        data={"pool":["54.37.165.151"],"managed":[{"ip":"54.37.165.151",
               "mode":"routed-wg","peer":"dell-r530"}]}
        with patch.object(m,"CLI",Path("/tmp/mock-ipctl")), \
             patch.object(m.os,"access",return_value=True), \
             patch.object(Path,"is_file",return_value=True), \
             patch.object(Path,"is_symlink",return_value=False), \
             patch.object(Path,"stat",return_value=SimpleNamespace(st_uid=0,st_mode=0o100755)), \
             patch.object(m,"call",return_value=SimpleNamespace(returncode=0,stdout=json.dumps(data))):
            result=m.safe_cli()
            self.assertEqual(result["managed"][0]["mode"],"routed-wg")
        self.assertNotIn("54.37.165.151",m.RULE_BYTES.decode())

if __name__=="__main__":
    unittest.main()

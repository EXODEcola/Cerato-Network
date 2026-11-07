"""The OVH UI inspector must never leak IPs, secrets or mutate network state."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
import audit_live_ipv4_ui as m

SAMPLE={
    "primary_ipv4":"51.210.223.57",
    "pool":["54.37.165.151"],
    "managed":[{"ip":"54.37.165.151","mode":"routed-wg",
                "peer":"dell-r530","present_on_wan":False}],
    "mappings":0,
}

class ReadonlyUiAuditTests(unittest.TestCase):
    def test_safe_status_summarization(self):
        result=m.summarize_source(SAMPLE)
        self.assertEqual(result,{"status":"available","pool_size":1,
                                 "managed_count":1,"managed_routed_count":1})
        self.assertNotIn("54.37.165.151",json.dumps(result))

    def test_status_probe_does_not_print_payload(self):
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(
            returncode=0,stdout=json.dumps(SAMPLE),stderr="")):
            result=m.status_probe(["/usr/local/sbin/cerato-ipctl","status"])
        self.assertTrue(result["json_object"])
        self.assertIn("object",result)

    def test_markers_and_no_state_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"backend").mkdir()
            (root/"web").mkdir()
            (root/"backend/server.py").write_text(
                "if p=='/api/ip/allocations':\n"
                "    cerato_reject_routed_nat(b)\n")
            (root/"web/app.js").write_text(
                "function ceratoEnhanceIPv4(){}\n"
                "async function ceratoLoadIPv4Allocations(){}\n"
                "function updates(){}\n")
            (root/"web/index.html").write_text(
                "<html><body><div id='app'></div><script src='/app.js'></script></body></html>")
            before={p.relative_to(root).as_posix():p.read_bytes()
                    for p in root.rglob("*") if p.is_file()}
            def probe(command,**kwargs):
                if command[0].endswith("systemctl"):
                    return SimpleNamespace(returncode=0)
                return SimpleNamespace(returncode=0,stdout=json.dumps(SAMPLE),stderr="")
            with patch.object(m.subprocess,"run",side_effect=probe):
                report=m.audit(root)
            after={p.relative_to(root).as_posix():p.read_bytes()
                   for p in root.rglob("*") if p.is_file()}
            self.assertEqual(before,after)
            self.assertTrue(report["frontend_markers"]["frontend_ipv4_overlay"])
            self.assertTrue(report["backend_markers"]["backend_allocations_route"])
            self.assertTrue(report["html_anchor"]["has_app_id"])
            self.assertTrue(report["web_service_active"])
            text=json.dumps(report)
            self.assertNotIn("54.37.165.151",text)
            self.assertNotIn("51.210.223.57",text)
            self.assertNotIn("dell-r530",text)
            self.assertFalse(report["network_modified"])
            self.assertFalse(report["production_modified"])

    def test_missing_sources_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(m.safe_file(Path(tmp)/"missing"))
        self.assertEqual(m.summarize_source(None),{"status":"unavailable"})

if __name__=="__main__":
    unittest.main()

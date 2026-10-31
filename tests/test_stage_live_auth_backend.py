"""Fail-closed, private and non-activating 8787 auth cutover staging."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from stage_live_auth_backend import prepare, transform, StageError, MODULES


SOURCE = """# sensitive historic backend source; never emit
PASSWORD_VALUE = 'PRIVATE-NOT-FOR-RELEASE'
def netstate(): return {'x': 1}
class Handler(object):
    def check_session(self,write=False): return True
    def send_json(self,code,body): return (code,body)
    def do_GET(self): return self.send_json(200,netstate())
    def do_POST(self): return self.send_json(200,{'ok':True})
if __name__ == '__main__':
    pass
"""


class PrivateAuthStagingTests(unittest.TestCase):
    def test_stages_private_modules_but_changes_no_live_files(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            live=root/"live-server.py"
            live.write_text(SOURCE,encoding="utf8")
            before=live.read_bytes()
            base=root/"baseline.json"
            base.write_text(json.dumps({"server_sha256": hashlib.sha256(before).hexdigest()}))
            out=root/"private-stage"
            report=prepare(live,out,baseline=base)
            self.assertTrue(report["backend_hash_verified"])
            self.assertFalse(report["ready_for_production"])
            self.assertFalse(report["production_modified"])
            self.assertFalse(report["nginx_modified"])
            self.assertFalse(report["network_modified"])
            self.assertEqual(report["module_count"],len(MODULES))
            self.assertEqual(live.read_bytes(),before)
            self.assertEqual(out.stat().st_mode & 0o777,0o700)
            staged=out/"backend/server.py"
            self.assertEqual(staged.stat().st_mode & 0o777,0o600)
            content=staged.read_text()
            self.assertIn("@_cerato_secure_handler",content)
            self.assertEqual(content.count("class Handler(object):"),1)
            self.assertIn("PRIVATE-NOT-FOR-RELEASE",content)
            self.assertNotIn("PRIVATE-NOT-FOR-RELEASE",json.dumps(report))
            self.assertEqual(set((out/"security").iterdir()),
                {out/"security"/module for module in MODULES})
            compile(content,"server.py","exec")

    def test_unknown_hash_blocks_before_write(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            live=root/"server.py"
            live.write_text(SOURCE,encoding="utf8")
            base=root/"baseline.json"
            base.write_text(json.dumps({"server_sha256":"0"*64}))
            out=root/"staging"
            with self.assertRaises(StageError):
                prepare(live,out,baseline=base)
            self.assertFalse(out.exists())

    def test_duplicate_handlers_or_existing_decoration_is_rejected(self):
        digest=hashlib.sha256(SOURCE.encode()).hexdigest()
        duplicate=SOURCE+"""
class Another:
    def check_session(self): return True
    def send_json(self): return None
    def do_GET(self): return None
    def do_POST(self): return None
"""
        with self.assertRaises(StageError):
            transform(duplicate,hashlib.sha256(duplicate.encode()).hexdigest())
        decorated=SOURCE.replace("class Handler(object):",
                                  "@decorate\nclass Handler(object):")
        with self.assertRaises(StageError):
            transform(decorated,hashlib.sha256(decorated.encode()).hexdigest())
        with self.assertRaises(StageError):
            transform(SOURCE,digest[:5]+"0"*59)

    def test_repeat_injection_is_refused(self):
        digest=hashlib.sha256(SOURCE.encode()).hexdigest()
        once=transform(SOURCE,digest)
        with self.assertRaises(StageError):
            transform(once,hashlib.sha256(once.encode()).hexdigest())


if __name__=="__main__":
    unittest.main()

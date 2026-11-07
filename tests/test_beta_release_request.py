"""No arbitrary release/channel/command can be dispatched by request JSON."""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from check_beta_release_request import validate,BetaRequestError

OK={"schema":"cerato-beta-publication-request-v1",
    "version":"v0.1.1-beta.1","from_version":"v0.1.0-beta.1",
    "channel":"beta","release_kind":"routed-ui"}

class BetaReleaseRequestTests(unittest.TestCase):
    def test_accepts_exact_upgrade_target(self):
        parsed=validate(OK)
        self.assertEqual(parsed["version"],"v0.1.1-beta.1")
        self.assertEqual(parsed["from_version"],"v0.1.0-beta.1")
    def test_accepts_scoped_nat_readout_beta(self):
        data={**OK,"version":"v0.1.2-beta.1",
              "from_version":"v0.1.1-beta.1","release_kind":"nat-ui"}
        accepted=validate(data)
        self.assertEqual(accepted["release_kind"],"nat-ui")
        self.assertEqual(accepted["from_version"],"v0.1.1-beta.1")

    def test_rejects_wrong_channel_or_content(self):
        for field,value in (("channel","stable"),("channel","dev"),
                            ("release_kind","full-backend"),
                            ("version","v0.1.1-dev.1"),
                            ("version","v0.1.0-beta.1"),
                            ("from_version","v0.1.1-beta.2")):
            with self.subTest(field=field,value=value), self.assertRaises(BetaRequestError):
                validate({**OK,field:value})
    def test_rejects_extra_fields_or_injection(self):
        for item in ({**OK,"shell_command":"rm -rf /"},
                     {**OK,"version":"v0.1.1-beta.1;echo"},[],
                     {**OK,"schema":"unknown"}):
            with self.assertRaises(BetaRequestError):
                validate(item)

if __name__=="__main__":
    unittest.main()

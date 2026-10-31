"""Contract for opt-in Cerato Build runner: no runner job or signing without approval."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class CeratoBuildRunnerContractTests(unittest.TestCase):
    def test_runner_is_explicitly_opt_in_and_never_signs(self):
        workflow=(ROOT/".github/workflows/cerato-build.yml").read_text()
        self.assertIn("tags:",workflow)
        self.assertIn("vars.CERATO_NETWORK_BUILD_ENABLED == 'true'",workflow)
        self.assertIn("CERATO_TRUSTED_TAG_FINGERPRINT",workflow)
        self.assertIn("runs-on: [self-hosted, Linux, X64, cerato-build]",workflow)
        self.assertIn("prepare-approved-tag.sh",workflow)
        self.assertIn("persist-credentials: false",workflow)
        self.assertIn('test ! -e "$OUT/manifest.sig"',workflow)
        for forbidden in ("--signing-key","ssh ","scp ","systemctl restart",
                          "cerato-updatectl install","release-source.json"):
            self.assertNotIn(forbidden,workflow)
        self.assertIn('"installable":false',workflow)

    def test_tag_build_script_accepts_only_external_venv(self):
        script=(ROOT/"scripts/prepare-approved-tag.sh").read_text()
        self.assertIn("CERATO_BUILD_PYTHON",script)
        self.assertIn('git verify-tag --raw "$VERSION"',script)
        self.assertIn('VALIDSIG',script)
        self.assertIn('git archive --format=tar "$VERSION"',script)
        self.assertIn('"$BUILD_PYTHON" "$WORKTREE/tools/release_pipeline.py" prepare',script)
        self.assertNotIn('sign_prepared(',script)


if __name__=="__main__":
    unittest.main()

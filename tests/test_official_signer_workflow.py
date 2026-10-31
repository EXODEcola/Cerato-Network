"""The official release workflow must not contact Build or expose unverified code."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class OfficialSignerWorkflowTests(unittest.TestCase):
    def test_protected_signer_fails_without_trust_and_verifies_before_publish(self):
        src=(ROOT/".github/workflows/publish-signed-release.yml").read_text()
        for entry in ("environment: cerato-network-signing",
                      "secrets.CERATO_ED25519_PRIVATE_PEM",
                      "vars.CERATO_SIGNING_PUBLIC_SHA256",
                      "test -n \"$SIGNING_PRIVATE_PEM\"",
                      "test \"$ACTUAL\" = \"$TRUSTED_PUBLIC_SHA256\"",
                      "stage_signed_static_release.py",
                      "gh release create",
                      "github.ref == 'refs/heads/main'",
                      "python3 -m unittest discover"):
            self.assertIn(entry,src)
        self.assertIn("python3 -m pip install --disable-pip-version-check -r security/requirements.txt",src)
        self.assertLess(src.index("Installer les dependances de test"),src.index("Tests complets AVANT signature"))
        self.assertLess(src.index("Tests complets AVANT signature"),src.index("Installer la cle uniquement"))
        # Never expose the Ed25519 secret at job level to arbitrary test code.
        secret_line="SIGNING_PRIVATE_PEM: ${{ secrets.CERATO_ED25519_PRIVATE_PEM }}"
        self.assertEqual(src.count(secret_line),1)
        self.assertGreater(src.index(secret_line),src.index("- name: Installer la cle uniquement"))
        self.assertLess(src.index("stage_signed_static_release.py"),src.index("gh release create"))
        self.assertNotIn("ssh ",src)
        self.assertNotIn("scp ",src)
        self.assertNotIn("runs-on: self-hosted",src)
        self.assertNotIn("cerato-updatectl apply",src)
        self.assertNotIn("CERATO_OVH_SSH_PRIVATE_KEY",src)

    def test_signing_workflow_not_triggered_by_unreviewed_pr(self):
        src=(ROOT/".github/workflows/publish-signed-release.yml").read_text()
        self.assertIn("workflow_dispatch:",src)
        self.assertIn("schedule:",src)
        self.assertNotIn("pull_request:",src)
        self.assertNotIn("push:\n",src)
        self.assertIn('options+=(--prerelease)',src)
        self.assertIn('--latest=false',src)
        self.assertIn("gh release upload",src)

if __name__=="__main__":
    unittest.main()

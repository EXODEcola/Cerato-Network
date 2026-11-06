"""Contract tests for Dev channel signed releases, without publisher credentials."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "updates"))

from build_release import RELEASE_PATTERN
from remote import _parse_version, CHANNELS, _channel_index, DistributionError
from channel_index import CHANNELS as INDEX_CHANNELS
from catalog import VERSION as CATALOG_VERSION
from compose_css_release import VERSION as CSS_VERSION
from compose_live_overlay import VERSION as WEB_VERSION


class DevChannelTests(unittest.TestCase):
    def test_dev_is_explicitly_supported_by_all_version_parsers(self):
        for validator in (RELEASE_PATTERN, CATALOG_VERSION,
                          CSS_VERSION, WEB_VERSION):
            self.assertIsNotNone(validator.fullmatch("v0.1.1-dev.1"))
            self.assertIsNone(validator.fullmatch("v0.1.1-hacked.1"))
        self.assertEqual(CHANNELS, {"stable", "beta", "dev"})
        self.assertEqual(INDEX_CHANNELS, CHANNELS)

    def test_semver_does_not_downgrade_beta_to_dev_same_base(self):
        self.assertLess(_parse_version("v0.1.0-dev.1"),
                        _parse_version("v0.1.0-beta.1"))
        self.assertLess(_parse_version("v0.1.0-beta.1"),
                        _parse_version("v0.1.0-rc.1"))
        self.assertLess(_parse_version("v0.1.0-rc.1"),
                        _parse_version("v0.1.0"))
        self.assertGreater(_parse_version("v0.1.1-dev.1"),
                           _parse_version("v0.1.0-beta.1"))
        self.assertGreater(_parse_version("v0.1.1-dev.2"),
                           _parse_version("v0.1.1-dev.1"))

    def test_dev_channel_rejects_beta_index_even_when_signed(self):
        pointer = {
            "schema": 1, "product": "cerato-network", "channel": "dev",
            "version": "v0.1.1-beta.1", "manifest_sha256": "a" * 64,
            "issued_at": 200, "expires_at": 1000,
        }
        raw = json.dumps(pointer).encode()
        def fake_get(url, limit, transport=None):
            return raw if url.endswith(".json") else b"signature"
        with patch("remote._get", side_effect=fake_get), patch(
            "remote.verify_signature", return_value=None
        ):
            with self.assertRaises(DistributionError):
                _channel_index("https://example.org/releases", "dev",
                               Path("/not-used.pub"), now=300)

    def test_beta_channel_rejects_dev_index_even_if_signature_is_valid(self):
        from build_release import canonical_json
        pointer = {
            "schema": 1, "product": "cerato-network", "channel": "beta",
            "version": "v0.1.1-dev.2", "manifest_sha256": "a" * 64,
            "issued_at": 200, "expires_at": 1000,
        }
        raw = canonical_json(pointer)
        def fake_get(url, limit, transport=None):
            return raw if url.endswith(".json") else b"signature"
        with patch("remote._get", side_effect=fake_get), patch(
            "remote.verify_signature", return_value=None
        ):
            with self.assertRaises(DistributionError):
                _channel_index("https://example.org/releases", "beta",
                               Path("/not-used.pub"), now=300)

    def test_dev_signed_index_can_pass_channel_gate(self):
        from build_release import canonical_json
        pointer = {
            "schema": 1, "product": "cerato-network", "channel": "dev",
            "version": "v0.1.1-dev.3", "manifest_sha256": "a" * 64,
            "issued_at": 200, "expires_at": 1000,
        }
        raw = canonical_json(pointer)
        def fake_get(url, limit, transport=None):
            return raw if url.endswith(".json") else b"signature"
        with patch("remote._get", side_effect=fake_get), patch(
            "remote.verify_signature", return_value=None
        ):
            out = _channel_index("https://example.org/releases", "dev",
                                 Path("/not-used.pub"), now=300)
        self.assertEqual(out["version"], "v0.1.1-dev.3")

    def test_workflow_uses_separate_scheduled_renewals_and_gated_signer(self):
        workflow = (ROOT / ".github" / "workflows" /
                    "publish-signed-release.yml").read_text()
        self.assertIn("options: [dev, beta, stable]", workflow)
        self.assertIn('cron: "28 4 * * 0,3"', workflow)
        self.assertIn("cerato-network-signing", workflow)
        self.assertIn("TRUSTED_PUBLIC_SHA256", workflow)
        self.assertIn("REQUEST_VERSION", workflow)
        self.assertIn('== *-dev.*', workflow)
        self.assertIn("--prerelease", workflow)


if __name__ == "__main__":
    unittest.main()

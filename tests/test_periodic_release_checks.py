"""Periodic release discovery must never become an unattended installer."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class PeriodicDiscoveryTests(unittest.TestCase):
    def test_only_signed_channel_check_is_scheduled(self):
        src=(ROOT/"scripts/enable-live-update-check.timer.sh").read_text(encoding="utf8")
        self.assertIn("ExecStart=/usr/local/sbin/cerato-updatectl check",src)
        self.assertIn("OnUnitInactiveSec=6h",src)
        self.assertIn("RandomizedDelaySec=15min",src)
        self.assertIn("ReadWritePaths=/var/lib/cerato-network-updates",src)
        self.assertIn("NoNewPrivileges=true",src)
        self.assertIn("systemctl enable --now cerato-network-update-check.timer",src)
        self.assertNotIn("cerato-updatectl apply",src)
        self.assertNotIn("cerato-network-update.service",src)
        self.assertNotIn("ssh ",src)
        self.assertNotIn("curl -k",src)
        self.assertNotIn("wg set",src)
        self.assertNotIn("nft ",src)
        self.assertNotIn("iptables ",src)

    def test_activation_cannot_install_timer_until_source_is_configured(self):
        src=(ROOT/"integrations/activate_live_updates.py").read_text(encoding="utf8")
        self.assertIn('if not existing.get("configured"):',src)
        self.assertIn("_start_periodic_checks()",src)
        self.assertLess(src.index('provision(BASE_URL,'),src.index("_start_periodic_checks()",src.index('def activate(')))
        self.assertIn('if install:',src)


if __name__=="__main__":
    unittest.main()

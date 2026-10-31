"""Regression checks for post-restart health and restored-panel readiness.

The shell function runs with stubbed systemctl/curl/sleep only; no system calls
to production are made in this test.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'finish-live-panel.sh'


def extract_wait():
    source = SCRIPT.read_text(encoding='utf8')
    start = source.index('wait_for_panel(){')
    end = source.index('\n}\n', start) + 2
    return source[start:end]


class InstallerReadinessTests(unittest.TestCase):
    def run_probe(self, mock):
        script = (
            'set -Eeuo pipefail\n'
            'SERVICE=cerato-network-web.service\n'
            + mock + '\n'
            + extract_wait() + '\n'
            'wait_for_panel\n'
        )
        return subprocess.run(['bash', '-c', script], capture_output=True,
                              text=True, timeout=4)

    def test_http_recovery_after_a_short_startup_delay(self):
        result = self.run_probe('''
attempt=0
systemctl(){
  case "$1" in
    is-active) return 0 ;;
    is-failed) return 1 ;;
    *) return 2 ;;
  esac
}
curl(){
  attempt=$((attempt+1))
  [[ "$attempt" -ge 4 ]]
}
sleep(){ :; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Port 8787 disponible après 4 contrôle(s)', result.stdout)

    def test_http_never_listens_is_reported(self):
        result = self.run_probe('''
systemctl(){
  case "$1" in
    is-active) return 0 ;;
    is-failed) return 1 ;;
  esac
}
curl(){ return 7; }
sleep(){ :; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('30 contrôles', result.stderr)

    def test_failed_service_does_not_loop(self):
        result = self.run_probe('''
systemctl(){
  case "$1" in
    is-active) return 1 ;;
    is-failed) return 0 ;;
  esac
}
curl(){ return 1; }
sleep(){ :; }
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Service Web en échec', result.stderr)

    def test_never_disables_current_login_as_part_of_visual_install(self):
        content = SCRIPT.read_text(encoding='utf8')
        self.assertNotIn('auth_basic off', content)
        self.assertNotIn('htpasswd', content)
        self.assertNotIn('wg set', content)
        self.assertNotIn('nft add', content)
        self.assertIn('cp -p "$BACKUP/$rel" "$LIVE/$rel"', content)
        self.assertIn('wait_for_panel', content)


if __name__ == '__main__':
    unittest.main()

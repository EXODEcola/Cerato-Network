"""Unit tests for the RISE-1 auth cutover gate; no live network mutations."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integrations'))
from check_live_auth_cutover import (BASELINE, CUTOVER_BLOCKERS, EXPECTED_ROUTES,
                                    REQUIRED_HOOKS, REQUIRED_SECTIONS,
                                    GateError, _load_json, assess)


class CutoverGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(BASELINE.read_text(encoding='utf-8'))

    def report(self):
        return {
            'format': 'cerato-live-auth-compat-v1',
            'api_routes': sorted(EXPECTED_ROUTES),
            'auth_hooks': sorted(REQUIRED_HOOKS),
            'ui_sections': sorted(REQUIRED_SECTIONS),
            'compatible_for_adapter_design': True,
            'direct_network_mutations': False,
            'server_bytes': 18607,
            'frontend_bytes': 34383,
            'server_sha256': self.baseline['server_sha256'],
            'frontend_sha256': self.baseline['frontend_sha256'],
        }

    def test_inventory_is_design_ready_but_never_deployment_ready(self):
        result = assess(self.report(), self.baseline)
        self.assertTrue(result['adapter_design_ready'])
        self.assertFalse(result['production_cutover_ready'])
        self.assertFalse(result['network_changes'])
        self.assertEqual(result['missing_known_routes'], [])
        self.assertEqual(result['unexpected_route_count'], 0)
        self.assertEqual(result['legacy_auth_must_be_retired'], ['/api/login', '/api/logout'])
        self.assertGreater(len(CUTOVER_BLOCKERS), 4)

    def test_unknown_api_must_block_design_without_echoing_untrusted_string(self):
        report = self.report()
        report['api_routes'].append('/api/secret-unreviewed')
        result = assess(report, self.baseline)
        self.assertFalse(result['adapter_design_ready'])
        self.assertEqual(result['unexpected_route_count'], 1)
        self.assertNotIn('secret-unreviewed', json.dumps(result))

    def test_missing_legacy_auth_handler_blocks_design(self):
        report = self.report()
        report['api_routes'].remove('/api/login')
        result = assess(report, self.baseline)
        self.assertFalse(result['adapter_design_ready'])
        self.assertEqual(result['missing_known_routes'], ['/api/login'])

    def test_source_drift_invalidates_baseline(self):
        report = self.report()
        report['server_sha256'] = '0' * 64
        self.assertFalse(assess(report, self.baseline)['adapter_design_ready'])
        report['server_sha256'] = 'malformed'
        self.assertFalse(assess(report, self.baseline)['adapter_design_ready'])

    def test_missing_hooks_and_sections_reject(self):
        report = self.report()
        report['auth_hooks'].remove('check_session')
        report['ui_sections'].remove('nat')
        result = assess(report, self.baseline)
        self.assertEqual(result['missing_required_hooks'], ['check_session'])
        self.assertEqual(result['missing_required_sections'], ['nat'])
        self.assertFalse(result['adapter_design_ready'])

    def test_invalid_readings_rejected(self):
        for key, value in [('server_bytes', True), ('frontend_bytes', 0),
                           ('direct_network_mutations', True),
                           ('compatible_for_adapter_design', False)]:
            report = self.report()
            report[key] = value
            self.assertFalse(assess(report, self.baseline)['adapter_design_ready'])
        report = self.report()
        report['api_routes'] = 'not a list'
        with self.assertRaises(GateError):
            assess(report, self.baseline)

    def test_symlink_and_oversize_reports_refused(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'report.json'
            p.write_text('{}', encoding='utf-8')
            link = Path(root) / 'link.json'
            link.symlink_to(p)
            with self.assertRaises(GateError):
                _load_json(link)
            p.write_text('a' * 20001, encoding='utf-8')
            with self.assertRaises(GateError):
                _load_json(p)


if __name__ == '__main__':
    unittest.main()

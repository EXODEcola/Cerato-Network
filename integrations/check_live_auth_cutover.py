#!/usr/bin/env python3
"""Read-only compatibility gate for the RISE-1 in-place auth migration.

This does NOT activate accounts, install services, patch the live server, or
configure networking. Structural compatibility is NOT deployment approval.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from inspect_live_auth_compat import InventoryError, inspect

BASELINE = Path(__file__).with_name('rise1_2026-10-30_baseline.json')
HEX_SHA256 = re.compile(r'^[0-9a-f]{64}$')
MAX_REPORT_BYTES = 20_000

# Routes detected on the running 8787 console. Two legacy authentication routes
# must be RETIRED at cutover, not forwarded through the new RBAC middleware.
LEGACY_AUTH_ROUTES = frozenset({'/api/login', '/api/logout'})

# These are the only network and read-only paths reviewed from the inventory;
# this inventory does not prove their HTTP verbs or implementations.
REVIEWED_ROUTES = frozenset({
    '/api/enroll/token', '/api/events', '/api/ip/add', '/api/ip/configure',
    '/api/ip/preview', '/api/ip/remove', '/api/nat/add', '/api/nat/remove',
    '/api/nft-preview', '/api/peers', '/api/peers/remove', '/api/session',
    '/api/status', '/api/updates', '/api/updates/check',
    '/api/updates/install', '/api/wg-config',
})
EXPECTED_ROUTES = REVIEWED_ROUTES | LEGACY_AUTH_ROUTES
REQUIRED_HOOKS = frozenset({'check_session', 'do_GET', 'do_POST', 'read_body', 'send_json'})
REQUIRED_SECTIONS = frozenset({
    'firewall', 'ips', 'logs', 'machines', 'nat', 'overview',
    'settings', 'topology', 'updates',
})

# Mandatory independent evidence not available from a names-only inventory.
CUTOVER_BLOCKERS = (
    'Revue manuelle des handlers, sessions et protections CSRF du backend actif',
    'Adaptateur RBAC et MFA branché sur TOUTES les anciennes routes API',
    'Anciennes routes /api/login et /api/logout rendues inaccessibles',
    'Tests HTTP bout en bout (owner/admin/user, MFA, CSRF, viewer expurgé)',
    'Migration et rollback éprouvés sur le service Web 8787',
    'Release compatible signée via GitHub Actions et installable depuis Cerato Network sans intervenir sur CERATO-BUILD-01',
)


class GateError(ValueError):
    """Invalid or untrusted metadata; no live writes are attempted."""


def _load_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT_BYTES:
        raise GateError('Inventaire ou référence absent, symbolique ou hors limites')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise GateError('JSON de compatibilité invalide') from exc
    if not isinstance(data, dict):
        raise GateError('Le rapport doit être un objet JSON')
    return data


def _valid_strings(value: object) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise GateError('Liste de métadonnées invalide')
    if len(value) != len(set(value)) or len(value) > 128:
        raise GateError('Métadonnées dupliquées ou excessives')
    return set(value)


def assess(report: dict, baseline: dict) -> dict:
    """Return only allowlisted findings; never echo arbitrary report values."""
    if not isinstance(report, dict) or not isinstance(baseline, dict):
        raise GateError('Rapport de compatibilité invalide')
    if baseline.get('format') != 'cerato-live-auth-baseline-v1':
        raise GateError('Format de référence inconnu')
    expected_server = baseline.get('server_sha256')
    expected_frontend = baseline.get('frontend_sha256')
    if any(not isinstance(v, str) or not HEX_SHA256.fullmatch(v)
           for v in (expected_server, expected_frontend)):
        raise GateError('Empreintes de référence invalides')
    routes = _valid_strings(report.get('api_routes'))
    hooks = _valid_strings(report.get('auth_hooks'))
    sections = _valid_strings(report.get('ui_sections'))
    if report.get('format') != 'cerato-live-auth-compat-v1':
        raise GateError('Version du rapport non prise en charge')
    hashes_valid = all(
        isinstance(report.get(key), str) and HEX_SHA256.fullmatch(report[key])
        for key in ('server_sha256', 'frontend_sha256')
    )
    sizes_valid = all(
        type(report.get(key)) is int and 0 < report[key] <= 2_000_000
        for key in ('server_bytes', 'frontend_bytes')
    )
    stable_hashes = (hashes_valid and
                     report['server_sha256'] == expected_server and
                     report['frontend_sha256'] == expected_frontend)
    expected_structure = (
        report.get('compatible_for_adapter_design') is True and
        report.get('direct_network_mutations') is False and
        REQUIRED_HOOKS.issubset(hooks) and REQUIRED_SECTIONS.issubset(sections)
    )
    missing_routes = sorted(EXPECTED_ROUTES - routes)
    unexpected_count = len(routes - EXPECTED_ROUTES)
    missing_hooks = sorted(REQUIRED_HOOKS - hooks)
    missing_sections = sorted(REQUIRED_SECTIONS - sections)
    # No untrusted route names are printed; only known missing names and counts.
    design_ready = bool(hashes_valid and sizes_valid and stable_hashes and
                        expected_structure and not missing_routes and not unexpected_count)
    return {
        'format': 'cerato-live-auth-cutover-gate-v1',
        'adapter_design_ready': design_ready,
        'production_cutover_ready': False,
        'source_hashes_match': bool(stable_hashes),
        'source_sizes_valid': bool(sizes_valid),
        'missing_known_routes': missing_routes,
        'unexpected_route_count': unexpected_count,
        'missing_required_hooks': missing_hooks,
        'missing_required_sections': missing_sections,
        'legacy_auth_must_be_retired': sorted(LEGACY_AUTH_ROUTES),
        'pending_cutover_guards': list(CUTOVER_BLOCKERS),
        'network_changes': False,
        'note': 'Rapport structurel uniquement. Aucun accès ni déploiement autorisé.',
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Cerato Network : préflight auth en lecture seule')
    parser.add_argument('--report', type=Path, help='Rapport JSON existant ; défaut : inventaire local')
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    args = parser.parse_args(argv)
    try:
        baseline = _load_json(args.baseline)
        report = _load_json(args.report) if args.report else inspect()
        result = assess(report, baseline)
    except (GateError, InventoryError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if result['adapter_design_ready'] else 2


if __name__ == '__main__':
    sys.exit(main())

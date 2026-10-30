#!/usr/bin/env python3
"""Read-only, allowlisted AST audit of the existing RISE-1 HTTP handlers.

No source code, tokens, arbitrary strings, environment values, network addresses
or sensitive literals are printed. Never change files/services/network state.
The result is an integration map, NOT a guarantee of authentication safety.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from inspect_live_auth_compat import (
    CLIENT, SERVER, InventoryError, _load, inspect,
)

VERBS = ('GET', 'POST', 'PATCH', 'DELETE')
REVIEWED_HOOKS = frozenset({
    'check_session', 'read_body', 'send_json', 'audit',
    'send_error', 'do_GET', 'do_POST', 'do_PATCH', 'do_DELETE',
})
MAX_CLASSES = 40
MAX_ROUTES = 128


class HandlerAuditError(ValueError):
    pass


def _called_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _method_calls(method: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    counts = {k: 0 for k in ('check_session', 'read_body', 'send_json', 'audit')}
    for n in ast.walk(method):
        if isinstance(n, ast.Call):
            name = _called_name(n)
            if name in counts:
                counts[name] += 1
    return counts


def _literal_route_conditions(method: ast.FunctionDef | ast.AsyncFunctionDef,
                              known: set[str]) -> set[str]:
    """Conservative: only route literals used in an if expression are counted."""
    observed = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.If):
            continue
        for test in ast.walk(node.test):
            if not isinstance(test, ast.Constant) or not isinstance(test.value, str):
                continue
            if test.value in known:
                observed.add(test.value)
    return observed


def audit(backend: Path = SERVER, frontend: Path = CLIENT) -> dict:
    base = inspect(backend, frontend)
    source = _load(backend)
    try:
        parsed = ast.parse(source, filename='server.py')
    except SyntaxError as exc:
        raise HandlerAuditError('Syntaxe du backend incompatible') from exc
    declared = set(base['api_routes'])
    if len(declared) > MAX_ROUTES:
        raise HandlerAuditError('Inventaire trop volumineux')
    classes = [n for n in ast.walk(parsed) if isinstance(n, ast.ClassDef)]
    if len(classes) > MAX_CLASSES:
        raise HandlerAuditError('Trop de classes pour une analyse fiable')
    handlers = []
    for node in classes:
        methods = {
            item.name: item for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name in {'do_' + v for v in VERBS} | {'check_session', 'send_json'}
        }
        active = [v for v in VERBS if 'do_' + v in methods]
        if not active:
            continue
        routes = {}
        calls = {}
        for verb in active:
            method = methods['do_' + verb]
            paths = _literal_route_conditions(method, declared)
            routes[verb] = sorted(paths)
            calls[verb] = _method_calls(method)
        handlers.append({
            'verbs': sorted(active),
            'has_check_session_method': 'check_session' in methods,
            'has_send_json_method': 'send_json' in methods,
            'conditional_routes': routes,
            'method_call_counts': calls,
        })
    if len(handlers) > 12:
        raise HandlerAuditError('Nombre de handlers HTTP inattendu')

    classified = set()
    for h in handlers:
        for paths in h['conditional_routes'].values():
            classified.update(paths)
    missing = sorted(declared - classified)
    return {
        'format': 'cerato-live-handler-map-v1',
        'backend_hash': base['server_sha256'],
        'frontend_hash': base['frontend_sha256'],
        'handler_candidates': handlers,
        'candidate_count': len(handlers),
        'unclassified_known_routes': missing,
        'unclassified_count': len(missing),
        'source_code_exported': False,
        'network_changes': False,
        'warning': 'Correspondance syntaxique seulement. Conditions, héritage, ordre '
                   'des contrôles, cookies et CSRF doivent être revus localement '
                   'avant toute activation de nouveaux comptes.',
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description='Audit local des handlers HTTP RISE-1 (lecture seule)')
    cli.add_argument('--backend', type=Path, default=SERVER)
    cli.add_argument('--frontend', type=Path, default=CLIENT)
    args = cli.parse_args(argv)
    try:
        report = audit(args.backend, args.frontend)
    except (InventoryError, HandlerAuditError, OSError, UnicodeError) as exc:
        cli.error(str(exc))
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

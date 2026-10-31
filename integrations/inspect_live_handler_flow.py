#!/usr/bin/env python3
"""Read-only, allowlisted AST audit of the existing RISE-1 HTTP handlers.

Never prints source code, credentials, arbitrary route names, environment
values, addresses or sensitive literals. This is an integration map, NOT
proof of authorization safety and NOT a deployment script.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from inspect_live_auth_compat import CLIENT, SERVER, InventoryError, _load, inspect
from check_live_auth_cutover import EXPECTED_ROUTES

VERBS = ('GET', 'POST', 'PATCH', 'DELETE')
MAX_CLASSES = 40
MAX_ROUTES = 128


class HandlerAuditError(ValueError):
    pass


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _method_calls(method: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    counts = {k: 0 for k in ('check_session', 'read_body', 'send_json', 'audit')}
    for node in ast.walk(method):
        if isinstance(node, ast.Call):
            name = _called_name(node)
            if name in counts:
                counts[name] += 1
    return counts


def _literal_route_conditions(method: ast.FunctionDef | ast.AsyncFunctionDef,
                              known: set[str]) -> set[str]:
    """Only fixed, already reviewed literals inside if-tests are emitted."""
    observed = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.If):
            continue
        for test in ast.walk(node.test):
            if isinstance(test, ast.Constant) and isinstance(test.value, str):
                if test.value in known:
                    observed.add(test.value)
    return observed



def _reachable_methods(entry, class_methods: dict, global_funcs: dict):
    """Conservatively follow local self.method() and module function calls.

    This reports POSSIBLE code paths, not proven authorization or runtime flow.
    No callee name, string literal or source code is included in the output.
    """
    pending=[('class',entry.name)]
    visited=set()
    reachable=[]
    while pending:
        scope,name=pending.pop()
        ident=(scope,name)
        if ident in visited:
            continue
        visited.add(ident)
        if len(visited)>64:
            raise HandlerAuditError('Graphe d’appels trop volumineux')
        target=class_methods.get(name) if scope=='class' else global_funcs.get(name)
        if target is None:
            continue
        reachable.append(target)
        for node in ast.walk(target):
            if not isinstance(node, ast.Call):
                continue
            fn=node.func
            if (isinstance(fn, ast.Attribute) and
                    isinstance(fn.value, ast.Name) and fn.value.id=='self' and
                    fn.attr in class_methods):
                pending.append(('class',fn.attr))
            elif isinstance(fn, ast.Name) and fn.id in global_funcs:
                pending.append(('global',fn.id))
    return reachable

def audit(backend: Path = SERVER, frontend: Path = CLIENT) -> dict:
    base = inspect(backend, frontend)
    source = _load(backend)
    try:
        parsed = ast.parse(source, filename='server.py')
    except SyntaxError as exc:
        raise HandlerAuditError('Syntaxe du backend incompatible') from exc
    discovered = set(base['api_routes'])
    if len(discovered) > MAX_ROUTES:
        raise HandlerAuditError('Inventaire trop volumineux')
    reviewed = discovered.intersection(EXPECTED_ROUTES)
    classes = [n for n in ast.walk(parsed) if isinstance(n, ast.ClassDef)]
    if len(classes) > MAX_CLASSES:
        raise HandlerAuditError('Trop de classes pour une analyse fiable')
    # Only top-level function definitions qualify as global callees.
    global_funcs={node.name:node for node in parsed.body
                  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    handlers = []
    for node in classes:
        methods = {
            item.name: item for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        active = [verb for verb in VERBS if 'do_' + verb in methods]
        if not active:
            continue
        routes = {}
        direct_routes = {}
        calls = {}
        delegate_counts = {}
        for verb in active:
            method = methods['do_' + verb]
            direct_routes[verb] = sorted(_literal_route_conditions(method, reviewed))
            reached = _reachable_methods(method, methods, global_funcs)
            all_routes=set()
            counts={k:0 for k in ('check_session','read_body','send_json','audit')}
            for helper in reached:
                all_routes.update(_literal_route_conditions(helper, reviewed))
                for k,v in _method_calls(helper).items():
                    counts[k]+=v
            routes[verb]=sorted(all_routes)
            calls[verb]=counts
            delegate_counts[verb]=max(0,len(reached)-1)
        handlers.append({
            'verbs': sorted(active),
            'has_check_session_method': 'check_session' in methods,
            'has_send_json_method': 'send_json' in methods,
            'conditional_routes': routes,
            'direct_conditional_routes': direct_routes,
            'reachable_delegate_counts': delegate_counts,
            'reachable_call_counts': calls,
            'method_call_counts': {verb: _method_calls(methods['do_'+verb]) for verb in active},
        })
    if len(handlers) > 12:
        raise HandlerAuditError('Nombre de handlers HTTP inattendu')
    classified = {
        path for handler in handlers
        for routes in handler['conditional_routes'].values() for path in routes
    }
    missing = sorted(reviewed - classified)
    return {
        'format': 'cerato-live-handler-map-v1',
        'backend_hash': base['server_sha256'],
        'frontend_hash': base['frontend_sha256'],
        'handler_candidates': handlers,
        'candidate_count': len(handlers),
        'unclassified_known_routes': missing,
        'unclassified_count': len(missing),
        'unreviewed_route_count': len(discovered - EXPECTED_ROUTES),
        'delegation_analysis': 'conservative-local-AST-v1',
        'source_code_exported': False,
        'network_changes': False,
        'warning': 'Graphe d’appels purement syntaxique, pas une validation RBAC. Conditions, héritage, ordre '
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

#!/usr/bin/env python3
"""Read-only, nonsecret status of historical login layers on the OVH gateway.

This is detection, NOT permission to switch off HTTP Basic or the old login.
No server code, configuration, passwords, usernames, keys, or Nginx snippets
are returned. Nginx dump is captured in-memory and never logged or exported.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
from inspect_live_auth_compat import SERVER, CLIENT, _load, inspect, InventoryError

AUTH_BASIC = re.compile(r'(?m)^\s*auth_basic\s+([^;]*?)\s*;')
AUTH_FILES = re.compile(r'(?m)^\s*auth_basic_user_file\s+[^;]+\s*;')
MAX_NGINX_BYTES = 3_000_000


def nginx_layer(command=('nginx','-T')) -> dict:
    try:
        proc = subprocess.run(command, timeout=8, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {'inspection': 'unavailable', 'http_basic_declared': None}
    if proc.returncode != 0 or len(proc.stdout) > MAX_NGINX_BYTES:
        return {'inspection': 'unavailable', 'http_basic_declared': None}
    # Do not return directives, paths or names from the production config.
    config = proc.stdout.decode('utf8', errors='replace')
    values = AUTH_BASIC.findall(config)
    return {
        'inspection': 'structural',
        'http_basic_declared': any(value.strip().lower()!='off' for value in values),
        'credential_file_directive_declared': bool(AUTH_FILES.search(config)),
        'effective_route_protection_verified': False,
    }


def inspect_layers(backend: Path = SERVER, frontend: Path = CLIENT) -> dict:
    inventory = inspect(backend,frontend)
    app = _load(frontend)
    paths = set(inventory['api_routes'])
    return {
        'format': 'cerato-live-login-layers-v1',
        'legacy_password_endpoint': '/api/login' in paths,
        'legacy_logout_endpoint': '/api/logout' in paths,
        'legacy_login_ui': bool(re.search(r'/api/login|Mot de passe administrateur',app)),
        'new_account_routes_live': '/api/auth/login' in paths,
        'new_mfa_routes_live': '/api/auth/mfa/verify' in paths,
        'gateway': nginx_layer(),
        'recommended_next_step': 'reviewed_auth_cutover',
        'safe_to_disable_existing_auth': False,
        'network_changes': False,
        'source_or_secrets_exported': False,
        'note': 'Nginx peut avoir plusieurs server/location ; présence d’une directive ne prouve pas son application à chaque route.',
    }


def main():
    parser=argparse.ArgumentParser(description='Inventaire des anciennes authentifications sans exposer de secrets')
    parser.add_argument('--backend',type=Path,default=SERVER)
    parser.add_argument('--frontend',type=Path,default=CLIENT)
    args=parser.parse_args()
    try:
        report=inspect_layers(args.backend,args.frontend)
    except (OSError,ValueError,UnicodeError,InventoryError) as exc:
        parser.error(str(exc))
    print(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=False))


if __name__=='__main__':
    main()

#!/usr/bin/env python3
"""Create a PRIVATE, inactive copy of a legacy 8787 auth migration.

This is NOT an installer: it neither changes nginx/systemd nor modifies the
original backend, accounts, WireGuard, NAT, firewall or addresses. No output
files containing source code may be published to GitHub or in release ZIPs.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path

from check_live_auth_cutover import BASELINE, _load_json

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "auth_store.py", "mfa.py", "secretbox.py", "legacy_policy.py",
    "live_session_guard.py", "legacy_auth_api.py", "live_http_bridge.py",
)
SERVER = Path("/opt/cerato-network/backend/server.py")
MAX_SIZE = 2_000_000
INJECTED = """
# CERATO_AUTH_BRIDGE_STAGED -- not an authorization decision by itself.
import os as _cerato_auth_os
import sys as _cerato_auth_sys
from pathlib import Path as _CeratoPath
_cerato_auth_sys.path.insert(0, str(_CeratoPath(__file__).resolve().parents[1] / "security"))
from auth_store import AuthStore as _CeratoAuthStore
from live_http_bridge import wrap_legacy_handler as _cerato_wrap

def _cerato_secure_handler(cls):
    origin = _cerato_auth_os.environ["CERATO_WEB_ORIGIN"]
    if not origin.startswith("https://"):
        raise RuntimeError("Origine HTTPS de confiance absente")
    store = _CeratoAuthStore(_CeratoPath("/var/lib/cerato-network-auth/accounts.sqlite3"))
    return _cerato_wrap(cls, store, allowed_origin=origin)

"""


class StageError(ValueError):
    pass


def _strict_read(path: Path, max_bytes: int = MAX_SIZE) -> bytes:
    if (path.is_symlink() or not path.is_file() or
            not 0 < path.stat().st_size <= max_bytes):
        raise StageError("Source inconnue, symbolique ou hors limites")
    return path.read_bytes()


def transform(source: str, expected_sha: str) -> str:
    if not isinstance(source, str) or not isinstance(expected_sha, str):
        raise StageError("Source invalide")
    actual = hashlib.sha256(source.encode("utf8")).hexdigest()
    if actual != expected_sha:
        raise StageError("Empreinte du backend non reconnue : migration refusée")
    if "CERATO_AUTH_BRIDGE_STAGED" in source:
        raise StageError("Migration déjà préparée")
    try:
        parsed = ast.parse(source)
    except SyntaxError as exc:
        raise StageError("Source Python non analysable") from exc
    classes = []
    for node in parsed.body:
        if not isinstance(node, ast.ClassDef):
            continue
        methods = {fn.name for fn in node.body
                   if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if {"do_GET", "do_POST", "check_session", "send_json"}.issubset(methods):
            classes.append(node)
    if len(classes) != 1 or classes[0].decorator_list:
        raise StageError("Classe HTTP ambiguë ou décorée : revue manuelle requise")
    target = classes[0]
    if target.lineno <= 1 or target.col_offset != 0:
        raise StageError("Classe HTTP dans une position incompatible")
    if not any(isinstance(n, ast.FunctionDef) and n.name == "netstate"
               for n in parsed.body):
        raise StageError("Backend réseau attendu non trouvé")
    lines = source.splitlines(keepends=True)
    line = lines[target.lineno - 1]
    if not line.startswith("class " + target.name + "(") and not line.startswith("class " + target.name + ":"):
        raise StageError("Déclaration de classe HTTP non reconnue")
    # Keep original code and private data byte-identical except this insertion.
    # We insert before the class declaration; future imports remain in place.
    insertion = INJECTED + "@_cerato_secure_handler\n"
    lines.insert(target.lineno - 1, insertion)
    patched = "".join(lines)
    compile(patched, "server.py", "exec")
    return patched


def prepare(backend: Path, destination: Path, *, baseline: Path = BASELINE,
            security_dir: Path = ROOT / "security") -> dict:
    original = _strict_read(backend)
    try:
        source = original.decode("utf8")
    except UnicodeError as exc:
        raise StageError("Encodage backend incompatible") from exc
    expected = _load_json(baseline).get("server_sha256")
    patched = transform(source, expected)
    target = destination.resolve()
    if (destination.exists() or backend.resolve() == target or
            backend.resolve().parent in target.parents or
            target in backend.resolve().parents):
        raise StageError("Destination existante ou imbriquée dans l'installation active")
    security_files = {}
    for filename in MODULES:
        security_files[filename] = _strict_read(security_dir / filename, max_bytes=200_000)
    # All validations complete before writing. Staged server.py may contain
    # private code/secrets and therefore must NEVER enter a public release.
    destination.mkdir(parents=True, mode=0o700)
    (destination / "backend").mkdir(mode=0o700)
    (destination / "security").mkdir(mode=0o700)
    p = destination / "backend" / "server.py"
    p.write_bytes(patched.encode("utf8"))
    p.chmod(0o600)
    for name, data in security_files.items():
        path = destination / "security" / name
        path.write_bytes(data)
        path.chmod(0o600)
    return {
        "format": "cerato-auth-staging-v1",
        "backend_hash_verified": True,
        "module_count": len(security_files),
        "source_or_secrets_exported": False,
        "production_modified": False,
        "nginx_modified": False,
        "network_modified": False,
        "ready_for_production": False,
        "next_requirement": "secure frontend integration and isolated HTTP end-to-end tests",
    }


def main():
    parser = argparse.ArgumentParser(description="Préparer hors production l'intégration d'authentification")
    parser.add_argument("--backend", type=Path, default=SERVER)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare(args.backend, args.destination)
    except (StageError, OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

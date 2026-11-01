#!/usr/bin/env python3
"""Repair a Python Cerato controller accidentally installed without its shebang.

This is a small scoped production hotfix: no changes to WireGuard, IP,
nftables, firewall, backend, Nginx, update keys, or routing persistence.
--check prints observations; --install refuses any unrecognized controller
content, backs up original, atomically installs corrected header, verifies
the direct CLI entrypoint, and restores its backup if validation fails.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

CONTROLLER = Path("/usr/local/sbin/ceratoctl")
BACKUPS = Path("/var/backups/cerato-network-inplace/ceratoctl-shebang")
# Observed AST-generated routed controller, before adding executable shebang.
BROKEN_SHA256 = "4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793"
SHEBANG = b"#!/usr/bin/env python3\n"
PYTHON = "/usr/bin/python3"


class RepairError(RuntimeError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def inspect(path=CONTROLLER):
    if path.is_symlink() or not path.is_file():
        raise RepairError("Contrôleur Cerato inexistant ou symbolique")
    metadata = path.stat()
    if metadata.st_size > 160_000 or metadata.st_uid != 0:
        raise RepairError("Contrôleur de taille ou propriétaire inattendu")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RepairError("Contrôleur modifiable par des utilisateurs non-root")
    source = path.read_bytes()
    missing = not source.startswith(b"#!")
    expected = sha256(source) == BROKEN_SHA256
    already_repaired = (source.startswith(SHEBANG) and
                        sha256(source[len(SHEBANG):]) == BROKEN_SHA256)
    # This validates syntax but does not import or execute the code.
    compile(source, str(path), "exec")
    return {"path": str(path), "sha256": sha256(source),
            "missing_shebang": missing, "known_broken_version": expected,
            "known_repaired_version": already_repaired,
            "recognized": expected or already_repaired,
            "network_modified": False}, source


def run_status(path):
    result = subprocess.run([str(path), "status"], capture_output=True,
                            text=True, timeout=12, check=False)
    if result.returncode:
        raise RepairError("Lancement direct ceratoctl status impossible")
    try:
        status = json.loads(result.stdout)
    except ValueError as exc:
        raise RepairError("Le contrôleur ne renvoie pas de JSON") from exc
    if not isinstance(status, dict):
        raise RepairError("Réponse Cerato inattendue")
    return status


def atomic(path, payload, mode):
    fd, name = tempfile.mkstemp(prefix=".ceratoctl-hotfix-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def repair(path=CONTROLLER, backups=BACKUPS):
    if os.geteuid() != 0:
        raise RepairError("Root requis")
    observation, original = inspect(path)
    if observation["known_repaired_version"]:
        run_status(path)
        return {"status": "already_repaired", "network_modified": False}
    if not observation["known_broken_version"] or not observation["missing_shebang"]:
        raise RepairError("Empreinte non reconnue : correctif refusé")
    # Establish that the current Python controller itself works with Python.
    raw = subprocess.run([PYTHON, str(path), "status"],
                         capture_output=True, text=True, timeout=12,
                         check=False)
    if raw.returncode:
        raise RepairError("Le contrôleur Python ne fonctionne pas : arrêt avant modification")
    try:
        parsed = json.loads(raw.stdout)
        if not isinstance(parsed, dict):
            raise ValueError()
    except ValueError as exc:
        raise RepairError("Sortie d'état du contrôleur non conforme") from exc
    if backups.is_symlink():
        raise RepairError("Dossier de sauvegardes symbolique")
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = backups / ("ceratoctl-" + stamp + ".py")
    if backup.exists() or backup.is_symlink():
        raise RepairError("Sauvegarde déjà existante")
    backup.write_bytes(original)
    backup.chmod(0o600)
    staged = SHEBANG + original
    compile(staged, str(path), "exec")
    if sha256(staged[len(SHEBANG):]) != BROKEN_SHA256:
        raise RepairError("Corruption de la version corrigée")
    mode = stat.S_IMODE(path.stat().st_mode)
    try:
        atomic(path, staged, mode)
        current, _ = inspect(path)
        if not current["known_repaired_version"]:
            raise RepairError("Vérification du fichier installé échouée")
        run_status(path)
    except BaseException:
        atomic(path, original, mode)
        raise
    return {"status": "repaired", "backup": str(backup),
            "direct_cli_validated": True, "network_modified": False,
            "web_restart_required": False}


def main():
    parser = argparse.ArgumentParser(description="Cerato root controller shebang safe hotfix")
    parser.add_argument("action", choices=["check", "install"], nargs="?", default="check")
    args = parser.parse_args()
    try:
        if args.action == "check":
            result, _ = inspect()
        else:
            result = repair()
    except (RepairError, OSError, ValueError, SyntaxError,
            subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

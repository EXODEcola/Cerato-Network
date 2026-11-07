#!/usr/bin/env python3
"""Grant legacy Web user ONLY privileged, read-only cerato-ipctl status.

One-time RISE-1 repair. Does not edit the Web source, Cerato configs,
WireGuard, nftables, routes, SSH, or any active network service.
The old sudo permissions remain untouched.

Usage (root): --check or --install.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

USER = "ceratonet"
CLI = Path("/usr/local/sbin/cerato-ipctl")
RULE = Path("/etc/sudoers.d/cerato-ipctl-status")
SUDO = "/usr/bin/sudo"
RUNUSER = "/usr/sbin/runuser"
RULE_BYTES = (
    "# Read-only routed IPv4 allocations for Cerato Network Web 8787.\n"
    "ceratonet ALL=(root) NOPASSWD: /usr/local/sbin/cerato-ipctl status\n"
).encode("utf8")


class ScopedSudoError(RuntimeError):
    pass


def call(*args, timeout=16):
    try:
        return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScopedSudoError("Commande de validation indisponible") from exc


def safe_cli():
    if CLI.is_symlink() or not CLI.is_file():
        raise ScopedSudoError("Contrôleur IPv4 absent ou symbolique")
    st = CLI.stat()
    if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ScopedSudoError("Contrôleur IPv4 non approuvé par root")
    if not os.access(CLI, os.X_OK):
        raise ScopedSudoError("Contrôleur IPv4 non exécutable")
    try:
        data = json.loads(call(str(CLI), "status").stdout)
    except ValueError as exc:
        raise ScopedSudoError("Statut IPv4 root non JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("managed"), list):
        raise ScopedSudoError("État IPv4 root absent ou invalide")
    return data


def service_account():
    p = call("systemctl", "show", "cerato-network-web.service", "-p", "User", "--value")
    if p.returncode or p.stdout.strip() != USER:
        raise ScopedSudoError("Service Web non exécuté sous ceratonet")
    if call("systemctl", "is-active", "--quiet", "cerato-network-web.service").returncode:
        raise ScopedSudoError("Service Web inactif")


def web_probe():
    p = call(RUNUSER, "-u", USER, "--", SUDO, "-n", str(CLI), "status")
    if p.returncode:
        return False
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return False
    return isinstance(data, dict) and isinstance(data.get("managed"), list)


def preflight():
    if os.geteuid() != 0:
        raise ScopedSudoError("Privilèges root nécessaires sur OVH")
    for path in (SUDO, RUNUSER):
        if not Path(path).is_file():
            raise ScopedSudoError("Dépendance système manquante")
    if shutil.which("visudo") is None:
        raise ScopedSudoError("visudo indisponible")
    if RULE.is_symlink():
        raise ScopedSudoError("Règle sudoers symbolique interdite")
    if RULE.exists():
        if not RULE.is_file() or RULE.read_bytes() != RULE_BYTES:
            raise ScopedSudoError("Une règle sudoers différente existe déjà : refus")
        meta = RULE.stat()
        if meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o440:
            raise ScopedSudoError("Permissions de la règle sudoers inattendues")
    parent = RULE.parent
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != 0:
        raise ScopedSudoError("Répertoire sudoers non approuvé")
    if parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ScopedSudoError("Permissions du répertoire sudoers insuffisantes")
    service_account()
    data = safe_cli()
    return {
        "pool_count": len(data.get("pool", [])) if isinstance(data.get("pool"), list) else None,
        "routed_count": sum(1 for row in data["managed"]
                            if isinstance(row, dict) and row.get("mode") == "routed-wg"),
        "web_status_access": web_probe(),
        "rule_present": RULE.exists(),
        "network_modified": False,
    }


def install():
    state = preflight()
    if RULE.exists():
        if not web_probe():
            raise ScopedSudoError("Règle déjà présente, mais le Web ne peut toujours pas lire le statut")
        return {"status": "already_authorized", **state}
    visudo = shutil.which("visudo")
    fd, temporary = tempfile.mkstemp(prefix=".cerato-ipctl-status-", dir=RULE.parent)
    temp = Path(temporary)
    changed = False
    try:
        os.fchmod(fd, 0o440)
        with os.fdopen(fd, "wb") as out:
            out.write(RULE_BYTES)
            out.flush()
            os.fsync(out.fileno())
        validation = call(visudo, "-cf", str(temp))
        if validation.returncode:
            raise ScopedSudoError("Règle sudoers refusée par visudo")
        # Do not overwrite files that appear after the initial preflight.
        if RULE.exists() or RULE.is_symlink():
            raise ScopedSudoError("Règle sudoers créée simultanément : refus")
        os.replace(temp, RULE)
        changed = True
        if not web_probe():
            raise ScopedSudoError("Contrôle sudo du service Web échoué après installation")
        return {"status": "authorized", "rule": "cerato-ipctl status only",
                "web_status_access": True, "routed_count": state["routed_count"],
                "network_modified": False, "service_restarted": False}
    except BaseException:
        if changed:
            RULE.unlink(missing_ok=True)
        raise
    finally:
        temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--install", action="store_true")
    args = parser.parse_args()
    try:
        result = preflight() if args.check else install()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    except (OSError, ValueError, ScopedSudoError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()

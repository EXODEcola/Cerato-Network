"""Read-only signed update catalog for the Cerato Network web console.

The management web process may inspect only a configured local staging
directory. It does not download untrusted URLs, call sudo or install packages.
A privileged deployment service will be integrated only after rollback tests.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from build_release import verify, PackageError

VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:dev|beta|rc)\.\d+)?$")


def release_info(release_dir: str = "", public_key: str = "", installed_version: str = "",
                 channel: str = "stable") -> dict:
    if channel not in ("stable","beta","dev"):
        return {"configured":False,"reason":"Canal invalide","installed_version":installed_version or None}
    if installed_version and not VERSION.fullmatch(installed_version):
        return {"configured":False,"reason":"Version locale invalide","installed_version":None}
    result={"configured":False,"channel":channel,"installed_version":installed_version or None,
            "verified":False,"available_version":None,"install_enabled":False}
    if not release_dir or not public_key:
        result["reason"]="Distribution signée non configurée"
        return result
    folder=Path(release_dir)
    key=Path(public_key)
    if not folder.is_dir() or folder.is_symlink() or not key.is_file() or key.is_symlink():
        result["reason"]="Emplacement de release ou clé publique indisponible"
        return result
    try:
        manifest=verify(folder,key)
    except (PackageError, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        result["reason"]="Release refusée : signature ou intégrité non valide"
        return result
    version=manifest["version"]
    if channel=="stable" and "-" in version:
        result["reason"]="Prerelease incompatible avec stable"
        return result
    if channel=="dev" and "-dev." not in version:
        result["reason"]="Release incompatible avec le canal Dev"
        return result
    if channel=="beta" and "-beta." not in version:
        result["reason"]="Release incompatible avec le canal Beta"
        return result
    result.update(configured=True, verified=True, available_version=version,
                  artifact_size=manifest["size"], sha256=manifest["sha256"],
                  reason="Release authentifiée et vérifiée (installation non activée)")
    return result


def configured_info() -> dict:
    return release_info(
        os.environ.get("CERATO_RELEASE_DIR",""),
        os.environ.get("CERATO_RELEASE_PUBKEY",""),
        os.environ.get("CERATO_INSTALLED_VERSION",""),
        os.environ.get("CERATO_RELEASE_CHANNEL","stable"),
    )

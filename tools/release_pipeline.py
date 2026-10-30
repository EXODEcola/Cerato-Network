#!/usr/bin/env python3
"""Cerato Network: separate artifact packaging from the trusted signing step.

Run `prepare` as the unprivileged build user after tests, then review the
manifest/artifact before executing `sign` under a dedicated signing identity.
Neither operation deploys code or changes the machine's network settings.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

from build_release import (
    RELEASE_PATTERN, PackageError, canonical_json, collect, sign,
    validate_archive, verify as verify_release, verify_signature,
)

ARTIFACT = "cerato-network-release.zip"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"


def _check_output_dir(folder: Path):
    if folder.is_symlink():
        raise PackageError("Répertoire de sortie symbolique interdit")
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    if folder.stat().st_mode & 0o022:
        raise PackageError("Répertoire de sortie modifiable par le groupe ou tous")


def _assert_regular_file(path: Path, limit: int):
    if path.is_symlink() or not path.is_file():
        raise PackageError("Fichier de release manquant ou symbolique")
    data = path.read_bytes()
    if not 0 < len(data) <= limit:
        raise PackageError("Fichier de release hors limites")
    return data


def _validate_unsigned(folder: Path):
    raw = _assert_regular_file(folder / MANIFEST, 32768)
    try:
        manifest = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise PackageError("Manifeste JSON invalide") from exc
    if (not isinstance(manifest, dict) or canonical_json(manifest) != raw or
        manifest.get("schema") != 1 or
        manifest.get("product") != "cerato-network" or
        manifest.get("signature_algorithm") != "ed25519" or
        manifest.get("artifact") != ARTIFACT or
        not RELEASE_PATTERN.fullmatch(str(manifest.get("version", ""))) or
        not re.fullmatch("[a-f0-9]{64}", str(manifest.get("sha256", "")))):
        raise PackageError("Manifeste de release non conforme")
    blob = _assert_regular_file(folder / ARTIFACT, 32_000_000)
    if len(blob) != manifest.get("size"):
        raise PackageError("Taille de release incorrecte")
    if hashlib.sha256(blob).hexdigest() != manifest["sha256"]:
        raise PackageError("Hachage SHA-256 incorrect")
    validate_archive(blob)
    return raw, manifest


def prepare(source: Path, output: Path, version: str):
    """Create a deterministic, unsigned archive using no secrets or signing key."""
    if not isinstance(version, str) or not RELEASE_PATTERN.fullmatch(version):
        raise PackageError("Version semver invalide")
    source = Path(source).resolve(strict=True)
    output = Path(output).resolve()
    if output == source or source in output.parents:
        raise PackageError("Sortie dans le dépôt refusée")
    _check_output_dir(output)
    # Refuse to overwrite an existing release or accidentally reuse a signature.
    for fname in (ARTIFACT, MANIFEST, SIGNATURE):
        if (output / fname).exists() or (output / fname).is_symlink():
            raise PackageError("Répertoire de sortie déjà utilisé : nouvelle destination requise")
    entries = collect(source)
    artifact = output / ARTIFACT
    try:
        with zipfile.ZipFile(artifact, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for name, file in entries:
                data = file.read_bytes()
                if len(data) > 4_000_000:
                    raise PackageError("Fichier modifié ou trop volumineux pendant le build")
                info = zipfile.ZipInfo("cerato-network/" + name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED,
                           compresslevel=9)
        content = artifact.read_bytes()
        validate_archive(content)
        manifest = {
            "schema": 1, "product": "cerato-network",
            "version": version, "artifact": ARTIFACT,
            "size": len(content), "sha256": hashlib.sha256(content).hexdigest(),
            "signature_algorithm": "ed25519",
        }
        (output / MANIFEST).write_bytes(canonical_json(manifest))
        _validate_unsigned(output)
    except BaseException:
        artifact.unlink(missing_ok=True)
        (output / MANIFEST).unlink(missing_ok=True)
        raise
    return manifest


def sign_prepared(folder: Path, private_key: Path):
    """Only the isolated signer uses the private key.

    Caller must review/approve the source commit and copy artifacts from the
    untrusted build workspace into the signer's controlled input directory.
    """
    folder = Path(folder)
    if folder.is_symlink():
        raise PackageError("Répertoire de signature symbolique interdit")
    _check_output_dir(folder)
    sigfile = folder / SIGNATURE
    if sigfile.exists() or sigfile.is_symlink():
        raise PackageError("Release déjà signée : remplacement interdit")
    raw, manifest = _validate_unsigned(folder)
    signature = sign(raw, Path(private_key))
    # Re-evaluate the archive digest to catch an update between check and sign.
    raw2, manifest2 = _validate_unsigned(folder)
    if raw != raw2 or manifest != manifest2:
        raise PackageError("Archive modifiée pendant la signature")
    with sigfile.open("xb") as dest:
        os.chmod(sigfile, 0o600)
        dest.write(signature)
        dest.flush()
        os.fsync(dest.fileno())
    return manifest


def verify_prepared(folder: Path, public_key: Path):
    return verify_release(Path(folder), Path(public_key))


def main():
    parser = argparse.ArgumentParser(description="Cerato Network — VPS build/sign")
    cmds = parser.add_subparsers(dest="action", required=True)
    p = cmds.add_parser("prepare", help="Tested source -> unsigned release")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--version", required=True)
    s = cmds.add_parser("sign", help="Approved release -> Ed25519 signature")
    s.add_argument("--output", required=True, type=Path)
    s.add_argument("--signing-key", required=True, type=Path)
    v = cmds.add_parser("verify", help="Check signed artifact with pinned public key")
    v.add_argument("--output", required=True, type=Path)
    v.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Ne pas exécuter ce pipeline sous root")
    try:
        if args.action == "prepare":
            result = prepare(args.source, args.output, args.version)
        elif args.action == "sign":
            result = sign_prepared(args.output, args.signing_key)
        else:
            result = verify_prepared(args.output, args.public_key)
    except (OSError, PackageError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        parser.error("Release refusée : " + str(exc))
    print(json.dumps({"ok": True, "version": result["version"], "sha256": result["sha256"]}))


if __name__ == "__main__":
    main()

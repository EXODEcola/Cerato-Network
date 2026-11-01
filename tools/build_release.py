#!/usr/bin/env python3
"""Create and verify signed Cerato Network archives on an independent build VPS.

Zero GitHub Actions / zero dependency on a specific hoster. Manifest Ed25519
signature is verified using OpenSSL (private key never leaves the build VPS).
Does NOT install anything or modify network settings.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

RELEASE_PATTERN = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-(?:dev|beta|rc)\.[0-9]+)?$")
REQUIRED = {"LICENSE", "README.md"}
BLOCKED_SEGMENTS = {".git", ".venv", "venv", "node_modules", "__pycache__",
                    "secrets", "private", "credentials", "artifacts", "dist"}
BLOCKED_EXTENSIONS = {".key", ".pem", ".p12", ".pfx", ".sqlite", ".db", ".log"}
BLOCKED_NAMES = {".env", "web-auth.json", "wg0.conf", "wg-cerato.conf",
                 "github.token", "update.json", "release-signing.key"}
MAX_FILES = 1000
MAX_FILE_SIZE = 4_000_000
MAX_UNCOMPRESSED = 80_000_000


class PackageError(Exception):
    pass


def canonical_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf8")


def forbidden_path(path: PurePosixPath) -> bool:
    parts = path.parts
    return (path.is_absolute() or ".." in parts or
            any(p in BLOCKED_SEGMENTS or p.startswith(".env.") for p in parts) or
            path.name in BLOCKED_NAMES or path.suffix.lower() in BLOCKED_EXTENSIONS or
            any("\\" in p or "\x00" in p for p in parts))


def collect(source: Path):
    if not source.is_dir() or source.is_symlink():
        raise PackageError("Source absente ou lien symbolique")
    entries = []
    total = 0
    for p in source.rglob("*"):
        rel = PurePosixPath(p.relative_to(source).as_posix())
        if forbidden_path(rel):
            continue
        if p.is_symlink():
            raise PackageError(f"Lien symbolique interdit: {rel}")
        if not p.is_file():
            continue
        if len(entries) >= MAX_FILES:
            raise PackageError("Archive : trop de fichiers")
        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            raise PackageError(f"Fichier trop volumineux : {rel}")
        total += size
        if total > MAX_UNCOMPRESSED:
            raise PackageError("Archive trop volumineuse")
        entries.append((rel.as_posix(), p))
    files = {name for name, _ in entries}
    if not REQUIRED.issubset(files):
        raise PackageError("Licence ou README absent")
    return sorted(entries)


def sign(payload: bytes, private_key: Path) -> bytes:
    if private_key.is_symlink() or not private_key.is_file():
        raise PackageError("Clé de signature introuvable ou lien symbolique")
    if private_key.stat().st_mode & 0o077:
        raise PackageError("Clé privée trop accessible : chmod 600 requis")
    with tempfile.TemporaryDirectory(prefix="cerato-sign-") as d:
        source = Path(d) / "manifest"
        result = Path(d) / "manifest.sig"
        source.write_bytes(payload)
        p = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                            "-inkey", str(private_key), "-in", str(source),
                            "-out", str(result)],
                           capture_output=True, timeout=15, check=False)
        if p.returncode:
            raise PackageError("Signature Ed25519 échouée")
        return result.read_bytes()


def verify_signature(payload: bytes, signature: bytes, public_key: Path):
    with tempfile.TemporaryDirectory(prefix="cerato-verify-") as d:
        data = Path(d) / "manifest"
        sig = Path(d) / "signature"
        data.write_bytes(payload)
        sig.write_bytes(signature)
        p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                            "-rawin", "-inkey", str(public_key),
                            "-in", str(data), "-sigfile", str(sig)],
                           capture_output=True, timeout=15, check=False)
        if p.returncode:
            raise PackageError("Signature de release invalide")


def validate_archive(archive: bytes):
    if len(archive) > 32_000_000:
        raise PackageError("Archive compressée trop volumineuse")
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        infolist = z.infolist()
        if not (0 < len(infolist) <= MAX_FILES):
            raise PackageError("Nombre de fichiers invalide")
        names = set()
        total = 0
        for entry in infolist:
            name = PurePosixPath(entry.filename)
            if (forbidden_path(name) or entry.filename.startswith("/") or
                len(name.parts) < 2 or name.parts[0] != "cerato-network" or
                entry.filename in names or entry.is_dir()):
                raise PackageError("Chemin archive interdit ou en double")
            names.add(entry.filename)
            if stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK:
                raise PackageError("Lien symbolique dans l'archive")
            if entry.file_size > MAX_FILE_SIZE:
                raise PackageError("Fichier décompressé trop volumineux")
            total += entry.file_size
        if total > MAX_UNCOMPRESSED:
            raise PackageError("Archive décompressée trop volumineuse")
        if not {"cerato-network/LICENSE", "cerato-network/README.md"}.issubset(names):
            raise PackageError("Archive incomplète")


def build(source: Path, out: Path, tag: str, private_key: Path):
    if not RELEASE_PATTERN.fullmatch(tag):
        raise PackageError("Version attendue : v1.2.3, v1.2.3-dev.1 ou v1.2.3-beta.1")
    source = source.resolve(strict=True)
    out = out.resolve()
    if out == source or source in out.parents:
        raise PackageError("La sortie doit se trouver hors des sources")
    entries = collect(source)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    asset = out / "cerato-network-release.zip"
    with zipfile.ZipFile(asset, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, p in entries:
            info = zipfile.ZipInfo("cerato-network/" + name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                       compresslevel=9)
    blob = asset.read_bytes()
    validate_archive(blob)
    manifest = {
        "schema": 1, "product": "cerato-network", "version": tag,
        "artifact": asset.name, "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "signature_algorithm": "ed25519",
    }
    raw_manifest = canonical_json(manifest)
    sig = sign(raw_manifest, private_key)
    (out / "manifest.json").write_bytes(raw_manifest)
    (out / "manifest.sig").write_bytes(sig)
    return manifest


def verify(out: Path, public_key: Path):
    raw = (out / "manifest.json").read_bytes()
    signature = (out / "manifest.sig").read_bytes()
    verify_signature(raw, signature, public_key)
    manifest = json.loads(raw)
    if (canonical_json(manifest) != raw or manifest.get("schema") != 1 or
        manifest.get("product") != "cerato-network" or
        manifest.get("signature_algorithm") != "ed25519" or
        not RELEASE_PATTERN.fullmatch(str(manifest.get("version", ""))) or
        manifest.get("artifact") != "cerato-network-release.zip"):
        raise PackageError("Manifeste non canonique ou invalide")
    blob = (out / "cerato-network-release.zip").read_bytes()
    if len(blob) != manifest.get("size") or hashlib.sha256(blob).hexdigest() != manifest.get("sha256"):
        raise PackageError("Intégrité de l'archive invalide")
    validate_archive(blob)
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Cerato Network - packaging VPS")
    sub = parser.add_subparsers(dest="action", required=True)
    b = sub.add_parser("build")
    b.add_argument("--source", required=True, type=Path)
    b.add_argument("--output", required=True, type=Path)
    b.add_argument("--version", required=True)
    b.add_argument("--signing-key", required=True, type=Path)
    v = sub.add_parser("verify")
    v.add_argument("--output", required=True, type=Path)
    v.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.action == "build":
            manifest = build(args.source, args.output, args.version, args.signing_key)
        else:
            manifest = verify(args.output, args.public_key)
        print(json.dumps({"ok": True, "version": manifest["version"], "sha256": manifest["sha256"]}))
    except (OSError, ValueError, PackageError, subprocess.TimeoutExpired, zipfile.BadZipFile) as err:
        sys.exit("Erreur de release: " + str(err))


if __name__ == "__main__":
    main()

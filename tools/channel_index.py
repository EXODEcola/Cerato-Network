#!/usr/bin/env python3
"""Produce a signed stable/beta discovery pointer on a separate signing host.

This is an explicit operator action, not a GitHub Action or an auto-signing
webhook. Requires a verified immutable signed release and a private key. The
result can be hosted as static HTTPS files; it does not upload anything.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from build_release import (PackageError, canonical_json, sign, verify,
                           verify_signature)
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"updates"))
from remote import _parse_version, DistributionError

CHANNELS={"stable","beta"}


def create_channel(release_dir: Path, channel: str, output: Path,
                   private_key: Path, public_key: Path, *,
                   issued_at: int | None=None, validity_seconds: int=86400):
    if channel not in CHANNELS:
        raise PackageError("Canal inconnu")
    if type(validity_seconds) is not int or not 300<=validity_seconds<=7*86400:
        raise PackageError("Durée de validité hors limites")
    release_dir=Path(release_dir)
    output=Path(output)
    if release_dir.is_symlink() or output.is_symlink():
        raise PackageError("Chemin symbolique refusé")
    verified=verify(release_dir,Path(public_key))
    version=verified["version"]
    if channel=="stable" and "-" in version:
        raise PackageError("Impossible de publier une beta sur stable")
    source=(release_dir/"manifest.json").read_bytes()
    now=int(time.time()) if issued_at is None else int(issued_at)
    if now<0:
        raise PackageError("Date de publication invalide")
    pointer={
        "schema":1,"product":"cerato-network","channel":channel,
        "version":version,"manifest_sha256":hashlib.sha256(source).hexdigest(),
        "issued_at":now,"expires_at":now+validity_seconds,
    }
    raw=canonical_json(pointer)
    signature=sign(raw,Path(private_key))
    verify_signature(raw,signature,Path(public_key))

    output.mkdir(parents=True,mode=0o700,exist_ok=True)
    if output.stat().st_mode & 0o077 or output.stat().st_uid!=os.geteuid():
        raise PackageError("Dossier channel non privé")
    dest=output/(channel+".json")
    sigdest=output/(channel+".sig")
    for file in (dest,sigdest):
        if file.is_symlink():
            raise PackageError("Fichier channel symbolique refusé")
    # Do not roll a live channel backwards, even if an older release has a
    # correct signature. Channel indexes are mutable but must be monotonic.
    if dest.exists() or sigdest.exists():
        if not (dest.is_file() and sigdest.is_file()):
            raise PackageError("Index incomplet")
        old_raw=dest.read_bytes()
        verify_signature(old_raw,sigdest.read_bytes(),Path(public_key))
        old=json.loads(old_raw)
        if old.get("channel")!=channel or _parse_version(old["version"])>=_parse_version(version):
            raise PackageError("Régression ou index identique interdits")
    with tempfile.TemporaryDirectory(prefix=".channel-",dir=output) as td:
        tmp=Path(td)
        (tmp/"pointer").write_bytes(raw)
        (tmp/"signature").write_bytes(signature)
        # These two files must be published atomically as a pair by the HTTPS
        # distributor, e.g. release directory + atomic symlink switch.
        # Local writes are not a transaction across multiple file names.
        os.replace(tmp/"pointer",dest)
        os.replace(tmp/"signature",sigdest)
    return pointer


def main():
    parser=argparse.ArgumentParser(description="Cerato Network signed channel index")
    parser.add_argument("--release",required=True,type=Path)
    parser.add_argument("--channel",choices=sorted(CHANNELS),required=True)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--signing-key",required=True,type=Path)
    parser.add_argument("--public-key",required=True,type=Path)
    parser.add_argument("--valid-seconds",type=int,default=86400)
    args=parser.parse_args()
    if os.geteuid()==0:
        parser.error("Ne pas publier une release sous root.")
    try:
        result=create_channel(args.release,args.channel,args.output,args.signing_key,
                              args.public_key,validity_seconds=args.valid_seconds)
    except (OSError,ValueError,KeyError,PackageError,DistributionError) as exc:
        parser.error("Publication refusée : "+str(exc))
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()

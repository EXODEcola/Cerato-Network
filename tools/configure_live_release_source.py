#!/usr/bin/env python3
"""One-time trusted-source provisioning for the existing RISE-1 update center.

Requires the 64-hex SHA256 fingerprint of the release Ed25519 PUBLIC key as
verified out of band. The browser can never change the pinned trust anchor.
No signing keys are generated, fetched or accepted here.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
from remote import _base,DistributionError

ROOT_CONFIG=Path("/etc/cerato-network")
KEY_OUT=ROOT_CONFIG/"release-verification.pub"
CONFIG=ROOT_CONFIG/"release-source.json"


def provision(source_url, public_key, fingerprint, channel):
    if os.geteuid()!=0:
        raise ValueError("Installation de la clé réservée à root")
    if channel not in ("stable","beta"):
        raise ValueError("Canal invalide")
    url=_base(source_url).rstrip("/")
    if not isinstance(fingerprint,str) or len(fingerprint)!=64 or any(c not in "0123456789abcdefABCDEF" for c in fingerprint):
        raise ValueError("Empreinte SHA-256 complète attendue")
    src=Path(public_key)
    if src.is_symlink() or not src.is_file() or src.stat().st_uid!=0:
        raise ValueError("Clé publique locale non approuvée par root")
    raw=src.read_bytes()
    if not 50<=len(raw)<=4096 or b"PRIVATE KEY" in raw:
        raise ValueError("Clé publique Ed25519 invalide")
    check=subprocess.run(["openssl","pkey","-pubin","-in",str(src),"-outform","DER"],
                         capture_output=True,timeout=8,check=False)
    if check.returncode!=0:
        raise ValueError("OpenSSL ne reconnaît pas la clé publique")
    actual=hashlib.sha256(check.stdout).hexdigest()
    if actual.lower()!=fingerprint.lower():
        raise ValueError("La clé de signature ne correspond pas à l'empreinte vérifiée")
    if CONFIG.is_symlink() or KEY_OUT.is_symlink():
        raise ValueError("Configuration symbolique refusée")
    if CONFIG.exists():
        raise ValueError("La source est déjà configurée : changement hors bande contrôlé requis")
    ROOT_CONFIG.mkdir(parents=True,exist_ok=True)
    fd,key_tmp=tempfile.mkstemp(prefix=".release-key-",dir=ROOT_CONFIG)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,"wb") as target:
            target.write(raw)
            target.flush()
            os.fsync(target.fileno())
        os.replace(key_tmp,KEY_OUT)
    finally:
        Path(key_tmp).unlink(missing_ok=True)
    config={"base_url":url,"channel":channel,"public_key":str(KEY_OUT)}
    fd,tmp=tempfile.mkstemp(prefix=".release-source-",dir=ROOT_CONFIG)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf8") as stream:
            json.dump(config,stream,sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,CONFIG)
    finally:
        Path(tmp).unlink(missing_ok=True)
    return {"url":url,"channel":channel,"public_key_fingerprint":actual,"configured":True}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description="Cerato Network release signature trust setup")
    parser.add_argument("--url",required=True)
    parser.add_argument("--public-key",required=True,type=Path)
    parser.add_argument("--fingerprint",required=True)
    parser.add_argument("--channel",choices=("stable","beta"),default="stable")
    args=parser.parse_args()
    try:
        print(json.dumps(provision(args.url,args.public_key,args.fingerprint,args.channel),
                         ensure_ascii=False))
    except (OSError,ValueError,DistributionError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))

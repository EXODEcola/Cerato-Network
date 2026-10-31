#!/usr/bin/env python3
"""Bootstrap a pinned OVH public release verification key from GitHub release.

The operator-supplied SHA-256 DER fingerprint MUST be independently approved
from the GitHub protected signing environment, not obtained from these files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from sync_github_signed_release import discover, _get, ASSETS, MAX, MirrorError
from stage_signed_static_release import validate


class BootstrapError(ValueError):
    pass


def approved_public_key(fingerprint,destination,channel="beta",*,get=_get):
    if not isinstance(fingerprint,str) or not re.fullmatch(r"[a-f0-9]{64}",fingerprint):
        raise BootstrapError("Empreinte Ed25519 publique approuvée invalide")
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        raise BootstrapError("Destination de clé non vierge")
    release=discover(channel,get=get)
    if release is None:
        raise BootstrapError("Aucune release officielle GitHub n'est encore publiée")
    version,urls=release
    with tempfile.TemporaryDirectory(prefix="cerato-initial-release-") as temp:
        root=Path(temp)
        pub=root/"public.pem"
        pub.write_bytes(get(urls["release-verification.pub"],4096))
        result=subprocess.run(["openssl","pkey","-pubin","-in",str(pub),"-outform","DER"],
                              capture_output=True,timeout=8,check=False)
        if result.returncode:
            raise BootstrapError("La clé publique GitHub n'est pas au format OpenSSL")
        actual=hashlib.sha256(result.stdout).hexdigest()
        if actual!=fingerprint:
            raise BootstrapError("Empreinte GitHub différente de l'autorité approuvée")
        bundle=root/"release"
        pointer=root/"channels"
        bundle.mkdir();pointer.mkdir()
        for name in ASSETS:
            (bundle/name).write_bytes(get(urls[name],MAX[name]))
        for name in (channel+".json",channel+".sig"):
            (pointer/name).write_bytes(get(urls[name],MAX[name]))
        verified,files=validate(bundle,pointer,pub,channel)
        if verified!=version:
            raise BootstrapError("Version signée discordante")
        fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(pub.read_bytes())
    return {"approved":True,"version":version,"channel":channel,
            "verified_signed_assets":len(files),"fingerprint":actual}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--fingerprint",required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--channel",default="beta",choices=["beta","stable"])
    args=parser.parse_args()
    try:
        print(json.dumps(approved_public_key(args.fingerprint,args.output,args.channel),
                         sort_keys=True,ensure_ascii=False))
    except (OSError,ValueError,BootstrapError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()

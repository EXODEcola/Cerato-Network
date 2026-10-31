#!/usr/bin/env python3
"""Safely expose ONLY already-signed release artifacts through OVH Nginx.

The initial publisher ran with umask 077, leaving release files at 0600,
the signed channel store at 0700. This script validates the existing
release against the root-pinned Ed25519 key BEFORE changing any permissions.

No network, nginx configuration, credentials, keys or payload bytes touched.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from publish_signed_release import (
    PUBLIC_ROOT,TRUST_CONFIG,_root,_trusted,_existing_channels,
    _require_root_owned,PublishError
)
from stage_signed_static_release import validate


class PermissionRepairError(ValueError):
    pass


def _require_owned(path:Path,*,directory:bool):
    if path.is_symlink() or (not path.is_dir() if directory else not path.is_file()):
        raise PermissionRepairError("Chemin public non régulier ou symbolique : "+str(path))
    info=path.stat()
    if info.st_uid!=0 or info.st_mode & 0o022:
        raise PermissionRepairError("Chemin public non protégé par root : "+str(path))


def plan(*,root=PUBLIC_ROOT,config=TRUST_CONFIG):
    root=Path(root)
    channel,key=_trusted(config)
    _root(root)
    pointer,_old=_existing_channels(root)
    if not pointer.is_symlink():
        raise PermissionRepairError("Canal actif non atomique : correction refusée")
    store=root/".channel-generations"
    _require_owned(store,directory=True)
    target=pointer.resolve(strict=True)
    if store.resolve(strict=True) not in target.parents:
        raise PermissionRepairError("Lien de canal hors du stockage approuvé")
    _require_owned(target,directory=True)
    indexfile=target/(channel+".json")
    _require_owned(indexfile,directory=False)
    metadata=json.loads(indexfile.read_bytes())
    version=metadata.get("version")
    # Parse untrusted filename before using it as a filesystem path.
    from remote import _parse_version
    _parse_version(version)
    release=root/"releases"/version
    _require_owned(release,directory=True)
    # Full Ed25519 verification: manifest, release archive and signed index,
    # expiry and from-version compatibility. Nothing is chmodded yet.
    validated,files=validate(release,target,key,channel)
    if validated!=version:
        raise PermissionRepairError("Version signée incohérente")
    expected_channel={channel+".json",channel+".sig"}
    expected_release={"manifest.json","manifest.sig","cerato-network-release.zip"}
    if not expected_channel.issubset({p.name for p in target.iterdir()}):
        raise PermissionRepairError("Canal incomplet")
    if {p.name for p in release.iterdir()}!=expected_release:
        raise PermissionRepairError("Release avec des fichiers inattendus")
    folders=[store,target,release]
    artifacts=[target/name for name in sorted(expected_channel)]
    artifacts.extend(release/name for name in sorted(expected_release))
    for part in folders:
        _require_owned(part,directory=True)
    for part in artifacts:
        _require_owned(part,directory=False)
    return {"version":version,"channel":channel,"folders":folders,
            "artifacts":artifacts,"verified_files":len(files)}


def repair(*,root=PUBLIC_ROOT,config=TRUST_CONFIG,install=False):
    data=plan(root=root,config=config)
    if install:
        if os.geteuid()!=0:
            raise PermissionRepairError("Correction réservée à root sur RISE-1")
        for part in data["folders"]:
            os.chmod(part,0o755)
        for part in data["artifacts"]:
            os.chmod(part,0o644)
    return {
        "release":data["version"],"channel":data["channel"],
        "signature_verified":True,
        "folders_checked":len(data["folders"]),
        "files_checked":len(data["artifacts"]),
        "modes_applied":bool(install),
        "network_modified":False,"nginx_modified":False,
        "release_contents_modified":False,
    }


def main():
    parser=argparse.ArgumentParser(description="Corriger les seules permissions publiques des releases signées")
    parser.add_argument("--install",action="store_true")
    args=parser.parse_args()
    try:
        print(json.dumps(repair(install=args.install),indent=2,sort_keys=True,
                         ensure_ascii=False))
    except (OSError,ValueError,TypeError,KeyError,PublishError) as exc:
        parser.error("Correction refusée : "+str(exc))


if __name__=="__main__":
    main()

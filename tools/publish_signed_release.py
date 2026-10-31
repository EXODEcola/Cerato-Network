#!/usr/bin/env python3
"""Publish ONLY independently signed RISE-1 visual releases to same-IP HTTPS.

Run on RISE-1 after the approved public key has been pinned through
configure_live_release_source.py, and the release artifacts have been
transferred from a separate signer. No release signatures are created here.
The channel changes via an atomic symlink swap; an immutable release directory
is installed before its channel pointer is published.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time

from stage_signed_static_release import validate, StagePublicationError

PUBLIC_ROOT=Path("/srv/cerato-releases/public/cerato-releases")
TRUST_CONFIG=Path("/etc/cerato-network/release-source.json")
EXPECTED_URL="https://51.210.223.57/cerato-releases"


class PublishError(ValueError):
    pass


def _trusted(config=TRUST_CONFIG):
    if config.is_symlink() or not config.is_file():
        raise PublishError("Clé publique non épinglée : source de mise à jour non configurée")
    metadata=config.stat()
    if metadata.st_uid!=0 or metadata.st_mode & 0o077:
        raise PublishError("Configuration de confiance non privée")
    data=json.loads(config.read_text(encoding="utf8"))
    if (not isinstance(data,dict) or set(data)!={"base_url","channel","public_key"}
            or data["base_url"].rstrip("/")!=EXPECTED_URL
            or data["channel"] not in ("stable","beta")):
        raise PublishError("Source HTTPS ou canal non approuvés")
    key=Path(data["public_key"])
    if (key.is_symlink() or not key.is_file() or
            key.stat().st_uid!=0 or key.stat().st_mode & 0o022):
        raise PublishError("Clé publique épinglée invalide")
    return data["channel"],key


def _root(path):
    if path.is_symlink() or not path.is_dir():
        raise PublishError("Racine de distribution absente ou lien symbolique")
    if path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
        raise PublishError("Répertoire public modifiable par un tiers")
    for name in ("releases",):
        part=path/name
        if part.is_symlink() or not part.is_dir() or part.stat().st_uid!=0:
            raise PublishError("Répertoire de releases inattendu")
        if part.stat().st_mode & 0o022:
            raise PublishError("Répertoire de releases non protégé")


def _write(path,data):
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,"wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def _existing_channels(root):
    current=root/"channels"
    if current.is_symlink():
        # Never follow a channel link outside its dedicated immutable store.
        relative=os.readlink(current)
        if not relative.startswith(".channel-generations/") or ".." in relative.split("/"):
            raise PublishError("Lien de canal non approuvé")
        location=(root/relative).resolve()
        if not location.is_dir() or (root/".channel-generations").resolve() not in location.parents:
            raise PublishError("Lien de canal sortant du dépôt")
    elif current.is_dir():
        location=current
    else:
        raise PublishError("Canaux non préparés")
    if location.stat().st_uid!=0 or location.stat().st_mode & 0o022:
        raise PublishError("Dossier de canaux non approuvé")
    snapshot={}
    for name in ("stable.json","stable.sig","beta.json","beta.sig"):
        source=location/name
        if source.is_symlink():
            raise PublishError("Fichier de canal symbolique interdit")
        if source.is_file():
            if source.stat().st_size>4096 or source.stat().st_size<=0:
                raise PublishError("Fichier de canal hors limites")
            snapshot[name]=source.read_bytes()
    if set(snapshot).intersection({"beta.json","beta.sig"}) in ({"beta.json"},{"beta.sig"}):
        raise PublishError("Paire beta incomplète")
    if set(snapshot).intersection({"stable.json","stable.sig"}) in ({"stable.json"},{"stable.sig"}):
        raise PublishError("Paire stable incomplète")
    return current,snapshot


def publish(release_dir,channel_dir,*,root=PUBLIC_ROOT,config=TRUST_CONFIG,
            install=False,now=None):
    channel,key=_trusted(config)
    version,files=validate(Path(release_dir),Path(channel_dir),key,channel,now=now)
    _root(root)
    current,old=_existing_channels(root)
    # Never serve an older version through a still-trusted channel.
    previous=old.get(channel+".json")
    if previous:
        from remote import _parse_version
        old_version=json.loads(previous)["version"]
        if _parse_version(version)<_parse_version(old_version):
            raise PublishError("Retour arrière de canal interdit")
        if version==old_version:
            old_index=json.loads(previous)
            proposed=json.loads(files["channels/"+channel+".json"])
            if old_index["manifest_sha256"]!=proposed["manifest_sha256"]:
                raise PublishError("Version déjà publiée avec un autre contenu")
    dest=root/"releases"/version
    expected={name.split("/")[-1]:data for name,data in files.items()
              if name.startswith("releases/")}
    if dest.is_symlink():
        raise PublishError("Release publiée symbolique interdite")
    if dest.exists():
        if not dest.is_dir() or {x.name for x in dest.iterdir()}!=set(expected):
            raise PublishError("Release existante incohérente")
        if any((dest/name).is_symlink() or (dest/name).read_bytes()!=data
               for name,data in expected.items()):
            raise PublishError("Conflit avec une version immuable")
    report={
        "format":"cerato-signed-static-publication-v1",
        "channel":channel,"version":version,
        "signature_verified":True,"immutable_release_verified":True,
        "installed":False,"network_modified":False,"nginx_modified":False,
        "update_trust_modified":False,
    }
    if not install:
        return report
    if os.geteuid()!=0:
        raise PublishError("Publication réservée à root")
    if not dest.exists():
        staging=Path(tempfile.mkdtemp(prefix=".incoming-",dir=root/"releases"))
        try:
            os.chmod(staging,0o755)
            for name,data in expected.items():
                _write(staging/name,data)
            os.rename(staging,dest)
        finally:
            if staging.exists():
                for file in staging.iterdir():
                    file.unlink()
                staging.rmdir()
    # Channel contents are served from one immutable generation.
    store=root/".channel-generations"
    if store.is_symlink():
        raise PublishError("Emplacement des générations symbolique")
    store.mkdir(mode=0o755,exist_ok=True)
    if store.stat().st_uid!=0 or store.stat().st_mode & 0o022:
        raise PublishError("Répertoire des générations non approuvé")
    stamp=str(time.time_ns())+"-"+str(os.getpid())
    generation=store/("generation-"+stamp)
    generation.mkdir(mode=0o755)
    old[channel+".json"]=files["channels/"+channel+".json"]
    old[channel+".sig"]=files["channels/"+channel+".sig"]
    for name,data in old.items():
        _write(generation/name,data)
    # Prepare relative symlink first, switch it only after all files exist.
    temporary=root/(".channels-next-"+stamp)
    os.symlink(".channel-generations/"+generation.name,temporary)
    try:
        if current.is_dir() and not current.is_symlink():
            # Initial empty directory from prepare-same-host-releases.sh:
            # migrate once. A short 404 during the first cutover cannot result
            # in unverified code execution.
            if list(current.iterdir()):
                raise PublishError("Canal initial non vide : migration manuelle requise")
            current.rmdir()
        os.replace(temporary,current)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    report["installed"]=True
    return report


def main():
    parser=argparse.ArgumentParser(description="Publier une release visuelle signée sur HTTPS OVH")
    parser.add_argument("--release",required=True,type=Path)
    parser.add_argument("--channels",required=True,type=Path)
    parser.add_argument("--install",action="store_true",help="Publier réellement après précontrôle")
    args=parser.parse_args()
    try:
        print(json.dumps(publish(args.release,args.channels,install=args.install),
                         ensure_ascii=False,sort_keys=True,indent=2))
    except (OSError,ValueError,KeyError,TypeError,StagePublicationError) as exc:
        parser.error("Publication refusée : "+str(exc))


if __name__=="__main__":
    main()

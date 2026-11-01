#!/usr/bin/env python3
"""Stage PUBLIC files for the already configured OVH static release path.

Requires signed immutable release + signed non-expired channel pointer from
an independently approved signer. Never generates signing keys, edits nginx,
contacts a server, or exposes a production backend. Only a validated
visual-only RISE-1 overlay is admitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
sys.path.insert(0,str(ROOT/"tools"))

from build_release import PackageError, canonical_json, verify, verify_signature
from remote import _parse_version, CHANNELS

BUNDLE="cerato-network-release.zip"
EXPECTED_OVERLAY="cerato-network/live-overlay/"
CSS_SCHEMA="cerato-network-legacy-web-css-v1"
CSS_FILES={EXPECTED_OVERLAY+"compat.json",EXPECTED_OVERLAY+"web/style.append.css"}
EXPECTED_FILES={
    EXPECTED_OVERLAY+"compat.json",
    EXPECTED_OVERLAY+"web/app.js",
    EXPECTED_OVERLAY+"web/style.css",
}
CHANNEL_FIELDS={"schema","product","channel","version","manifest_sha256",
                "issued_at","expires_at"}
MAX_INDEX=4096
MAX_SIGN=256


class StagePublicationError(ValueError):
    pass


def _read_regular(path:Path,limit:int)->bytes:
    if path.is_symlink() or not path.is_file():
        raise StagePublicationError("Fichier signé absent ou lien symbolique")
    size=path.stat().st_size
    if size<=0 or size>limit:
        raise StagePublicationError("Fichier signé hors limites")
    return path.read_bytes()


def validate(release_dir:Path,channel_dir:Path,public_key:Path,channel:str,
             *,now:int|None=None)->tuple[str,dict[str,bytes]]:
    if channel not in CHANNELS:
        raise StagePublicationError("Canal invalide")
    key=Path(public_key)
    if key.is_symlink() or not key.is_file():
        raise StagePublicationError("Clé publique approuvée absente")
    manifest=verify(Path(release_dir),key)
    version=manifest["version"]
    _parse_version(version)
    if channel=="stable" and "-" in version:
        raise StagePublicationError("Prerelease interdite sur stable")
    if channel=="dev" and "-dev." not in version:
        raise StagePublicationError("Le canal Dev exige -dev.N")
    if channel=="beta" and "-beta." not in version:
        raise StagePublicationError("Le canal beta exige -beta.N")
    pointer_bytes=_read_regular(Path(channel_dir)/(channel+".json"),MAX_INDEX)
    pointer_signature=_read_regular(Path(channel_dir)/(channel+".sig"),MAX_SIGN)
    verify_signature(pointer_bytes,pointer_signature,key)
    pointer=json.loads(pointer_bytes)
    if (not isinstance(pointer,dict) or set(pointer)!=CHANNEL_FIELDS or
            canonical_json(pointer)!=pointer_bytes or
            pointer["schema"]!=1 or pointer["product"]!="cerato-network" or
            pointer["channel"]!=channel or pointer["version"]!=version):
        raise StagePublicationError("Index de canal signé incompatible")
    current=int(time.time()) if now is None else int(now)
    issued=pointer["issued_at"]
    expiry=pointer["expires_at"]
    if (type(issued) is not int or type(expiry) is not int or
            expiry<=current or issued>current+300 or
            expiry<=issued or expiry-issued>7*86400):
        raise StagePublicationError("Index de canal expiré ou temporellement invalide")
    raw_manifest=_read_regular(Path(release_dir)/"manifest.json",32768)
    if hashlib.sha256(raw_manifest).hexdigest()!=pointer["manifest_sha256"]:
        raise StagePublicationError("Empreinte du manifeste différente de l'index")
    archive_path=Path(release_dir)/BUNDLE
    with zipfile.ZipFile(archive_path) as archive:
        found={x.filename for x in archive.infolist()}
        permitted=EXPECTED_FILES|{
            "cerato-network/LICENSE","cerato-network/README.md",
        }
        css_only=found==CSS_FILES|{
            "cerato-network/LICENSE","cerato-network/README.md",
        }
        if (not css_only and found!=permitted) or len(archive.infolist())!=len(found):
            raise StagePublicationError("Seul un overlay graphique RISE-1 est publiable")
            raise StagePublicationError("Seul un overlay graphique RISE-1 est publiable")
        spec=json.loads(archive.read(EXPECTED_OVERLAY+"compat.json"))
        if (not isinstance(spec,dict) or
                spec.get("schema") not in ("cerato-network-legacy-web-visual-v1",CSS_SCHEMA) or
                spec.get("target")!="cerato-network-web-8787" or
                not isinstance(spec.get("from_versions"),list) or
                not spec["from_versions"] or
                any(not isinstance(v,str) for v in spec["from_versions"])):
            raise StagePublicationError("Compatibilité RISE-1 non approuvée")
        if css_only:
            if spec["schema"]!=CSS_SCHEMA:
                raise StagePublicationError("Schéma du correctif CSS invalide")
            css=archive.read(EXPECTED_OVERLAY+"web/style.append.css")
            if (not css.startswith(b"/* CERATO-NETWORK-SIGNED-CSS-V1 */") or
                len(css)>200_000 or b"@import" in css.lower() or b"url(" in css.lower()):
                raise StagePublicationError("Correctif CSS non approuvé")
        elif spec["schema"]!="cerato-network-legacy-web-visual-v1":
            raise StagePublicationError("Schéma visuel complet invalide")
        for source in spec["from_versions"]:
            _parse_version(source)
            if _parse_version(source)>=_parse_version(version):
                raise StagePublicationError("Version source non antérieure")
    files={
        f"channels/{channel}.json":pointer_bytes,
        f"channels/{channel}.sig":pointer_signature,
        f"releases/{version}/manifest.json":raw_manifest,
        f"releases/{version}/manifest.sig":
            _read_regular(Path(release_dir)/"manifest.sig",MAX_SIGN),
        f"releases/{version}/{BUNDLE}":
            _read_regular(archive_path,32_000_000),
    }
    return version,files


def stage(release_dir:Path,channel_dir:Path,public_key:Path,channel:str,
          destination:Path,*,now:int|None=None)->dict:
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():
        raise StagePublicationError("Destination non vierge")
    root=destination.resolve()
    for path in (release_dir,channel_dir,public_key):
        p=Path(path).resolve()
        if root==p or p in root.parents or root in p.parents:
            raise StagePublicationError("Sortie imbriquée dans les données signées")
    version,files=validate(release_dir,channel_dir,public_key,channel,now=now)
    # All cryptographic & compatibility gates finish before the first write.
    destination.mkdir(parents=True,mode=0o700)
    for rel,data in files.items():
        path=destination/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
        os.chmod(path,0o644)
    return {
        "format":"cerato-signed-static-stage-v1",
        "version":version,
        "channel":channel,
        "files":sorted(files),
        "signature_verified":True,
        "visual_only":True,
        "public_base":"https://51.210.223.57/cerato-releases/",
        "published_to_ovh":False,
        "nginx_modified":False,
        "network_modified":False,
        "private_key_processed":False,
    }


def main():
    parser=argparse.ArgumentParser(description="Vérifier et préparer une distribution signée pour OVH")
    parser.add_argument("--release",type=Path,required=True)
    parser.add_argument("--channels",type=Path,required=True)
    parser.add_argument("--public-key",type=Path,required=True)
    parser.add_argument("--channel",choices=sorted(CHANNELS),default="beta")
    parser.add_argument("--destination",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=stage(args.release,args.channels,args.public_key,args.channel,args.destination)
    except (OSError,ValueError,KeyError,TypeError,PackageError,zipfile.BadZipFile) as exc:
        parser.error("Publication refusée : "+str(exc))
    print(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False))


if __name__=="__main__":
    main()

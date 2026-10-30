#!/usr/bin/env python3
"""Prepare exactly three reviewed legacy Web files for a signed release.

Run on CERATO-BUILD-01, not OVH. This produces only source tree data, not a
signature. The separate, approved release pipeline signs an archive later.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil

SCHEMA="cerato-network-legacy-web-overlay-v1"
FILES=("backend/server.py","web/app.js","web/style.css")
VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?$")


class OverlayError(Exception):
    pass


def compose(source:Path,destination:Path,from_versions:list[str]):
    source=Path(source)
    destination=Path(destination)
    if not from_versions or len(set(from_versions))!=len(from_versions) or not all(VERSION.fullmatch(x) for x in from_versions):
        raise OverlayError("Liste de versions sources invalide")
    if source.is_symlink() or not source.is_dir() or destination.is_symlink() or destination.exists():
        raise OverlayError("Source absente ou destination existante")
    if destination.resolve()==source.resolve() or source.resolve() in destination.resolve().parents:
        raise OverlayError("Destination imbriquée dans la source")
    read={}
    for rel in FILES:
        path=source/rel
        if path.is_symlink() or not path.is_file():
            raise OverlayError("Source Web manquante ou symbolique : "+rel)
        if not 0<path.stat().st_size<=2_000_000:
            raise OverlayError("Source Web trop volumineuse ou vide : "+rel)
        read[rel]=path.read_bytes()
    # Strict, no network configs, /etc files, DBs or WireGuard keys.
    destination.mkdir(parents=True,mode=0o700)
    for rel,blob in read.items():
        target=destination/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(blob)
    (destination/"compat.json").write_text(
        json.dumps({"schema":SCHEMA,"target":"cerato-network-web-8787",
                    "from_versions":from_versions},sort_keys=True)+"\n",
        encoding="utf8")
    return {"files":list(FILES),"from_versions":from_versions,"approved":False}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description="Cerato Network approved legacy Web overlay")
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--destination",required=True,type=Path)
    parser.add_argument("--from-version",action="append",required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(compose(args.source,args.destination,args.from_version),
                         ensure_ascii=False))
    except (OverlayError,OSError) as exc:
        parser.error(str(exc))

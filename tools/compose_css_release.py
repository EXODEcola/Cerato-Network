#!/usr/bin/env python3
"""Prepare a conservative CSS-only *legacy 8787* update from reviewed repo bytes.

Never ships the development app.js or historical backend. Use only a
reviewed, static additive stylesheet intended for the installed Graphite UI.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

SCHEMA="cerato-network-legacy-web-css-v1"
MARKER=b"/* CERATO-NETWORK-SIGNED-CSS-V1 */"
VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?$")


class CSSReleaseError(ValueError):
    pass


def compose(source:Path,destination:Path,from_versions:list[str]):
    source=Path(source)
    destination=Path(destination)
    if (not from_versions or len(set(from_versions))!=len(from_versions)
            or any(not VERSION.fullmatch(x) for x in from_versions)):
        raise CSSReleaseError("Versions sources incorrectes")
    if source.is_symlink() or not source.is_file() or destination.exists() or destination.is_symlink():
        raise CSSReleaseError("Source inconnue ou destination déjà existante")
    if source.resolve() in destination.resolve().parents:
        raise CSSReleaseError("Destination imbriquée")
    css=source.read_bytes()
    if (not MARKER==css[:len(MARKER)] or
            not 0<len(css)<=200_000 or b"@import" in css.lower() or
            b"url(" in css.lower()):
        raise CSSReleaseError("Correctif CSS non approuvé")
    destination.mkdir(mode=0o700,parents=True)
    (destination/"web").mkdir(mode=0o700)
    (destination/"web/style.append.css").write_bytes(css)
    (destination/"compat.json").write_text(json.dumps({
        "schema":SCHEMA,"target":"cerato-network-web-8787",
        "from_versions":from_versions,
    },sort_keys=True)+"\n",encoding="utf8")
    return {"format":"cerato-css-addon-stage-v1","visual_only":True,
            "files":["web/style.append.css","compat.json"],
            "backend_included":False,"frontend_js_included":False}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--destination",type=Path,required=True)
    parser.add_argument("--from-version",action="append",required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(compose(args.source,args.destination,args.from_version),sort_keys=True))
    except (OSError,CSSReleaseError) as exc:
        parser.error(str(exc))

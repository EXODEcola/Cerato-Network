#!/usr/bin/env python3
"""Compose a narrowly approved, signed, UI-only routed NAT readout.

The resulting release contains only an append-only JS function and compat
metadata. No backend, secrets, WireGuard or OVH source files are copied.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

SCHEMA="cerato-network-legacy-routed-nat-readout-v1"
MARKER=b"/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */"
VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?$")

class NATReadoutReleaseError(ValueError):
    pass

def compose(source:Path,destination:Path,from_versions:list[str])->dict:
    if (not from_versions or len(set(from_versions))!=len(from_versions) or
        any(not VERSION.fullmatch(v) for v in from_versions)):
        raise NATReadoutReleaseError("Version cible non approuvée")
    source=Path(source)
    destination=Path(destination)
    if (source.is_symlink() or not source.is_file() or
        not 0<source.stat().st_size<=16000):
        raise NATReadoutReleaseError("Correctif graphique absent")
    if destination.exists() or destination.is_symlink():
        raise NATReadoutReleaseError("Destination non vierge")
    code=source.read_bytes()
    if (not code.startswith(MARKER) or
        code.count(b"function ceratoRenderDirectRoutedIPv4(")!=1 or
        b"innerHTML" in code or b"fetch(" in code or b"eval(" in code):
        raise NATReadoutReleaseError("Correctif JavaScript inattendu")
    import subprocess
    syntax=subprocess.run(["node","--check","-"],input=code,capture_output=True,
                          timeout=10,check=False)
    if syntax.returncode!=0:
        raise NATReadoutReleaseError("Syntaxe JavaScript invalide")
    (destination/"web").mkdir(mode=0o700,parents=True)
    (destination/"compat.json").write_text(json.dumps({
        "schema":SCHEMA,
        "target":"cerato-network-web-8787",
        "from_versions":from_versions,
    },sort_keys=True)+"\n",encoding="utf8")
    (destination/"web/routed-nat-panel.js").write_bytes(code)
    return {"schema":SCHEMA,"files":["compat.json","web/routed-nat-panel.js"],
            "backend_in_archive":False,"frontend_source_in_archive":False,
            "network_modified":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--destination",type=Path,required=True)
    p.add_argument("--from-version",action="append",required=True)
    args=p.parse_args()
    try:
        print(json.dumps(compose(args.source,args.destination,args.from_version),
                         sort_keys=True))
    except (NATReadoutReleaseError,OSError,ValueError) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

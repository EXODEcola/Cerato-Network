#!/usr/bin/env python3
"""Compose an immutable signed approval, never a copy of live OVH Web sources."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

SCHEMA="cerato-network-legacy-routed-ui-patch-v1"
VERSION=re.compile(r"^v\d+\.\d+\.\d+(?:-(?:dev|beta|rc)\.\d+)?$")
HEX=re.compile(r"^[0-9a-f]{64}$")

class RoutedReleaseError(ValueError):
    pass

def source_hashes(code):
    values={}
    for node in ast.parse(code).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1:
            target=node.targets[0]
            if (isinstance(target,ast.Name) and target.id in
                    ("LIVE_BACKEND_SHA256","LIVE_FRONTEND_SHA256") and
                    isinstance(node.value,ast.Constant)):
                values[target.id]=node.value.value
    if (set(values)!={"LIVE_BACKEND_SHA256","LIVE_FRONTEND_SHA256"}
            or any(not isinstance(x,str) or not HEX.fullmatch(x)
                   for x in values.values())):
        raise RoutedReleaseError("Empreintes de la base OVH manquantes")
    return values

def compose(patch:Path,model:Path,destination:Path,from_versions:list[str]):
    if (not from_versions or len(set(from_versions))!=len(from_versions)
            or any(not VERSION.fullmatch(v) for v in from_versions)):
        raise RoutedReleaseError("Version source invalide")
    destination=Path(destination)
    sources=(Path(patch),Path(model))
    if destination.exists() or destination.is_symlink():
        raise RoutedReleaseError("Destination déjà présente")
    for file in sources:
        if file.is_symlink() or not file.is_file() or not 0<file.stat().st_size<=300000:
            raise RoutedReleaseError("Source patcher/modèle invalide")
    patch_source=sources[0].read_text(encoding="utf8")
    model_source=sources[1].read_text(encoding="utf8")
    ast.parse(model_source)
    if ("def patch_backend(" not in patch_source
            or "def patch_frontend(" not in patch_source
            or "def summarize(" not in model_source):
        raise RoutedReleaseError("Outils IPv4 incorrects")
    baselines=source_hashes(patch_source)
    manifest={
        "schema":SCHEMA,
        "backend_sha256":baselines["LIVE_BACKEND_SHA256"],
        "frontend_sha256":baselines["LIVE_FRONTEND_SHA256"],
        "patch_sha256":hashlib.sha256(sources[0].read_bytes()).hexdigest(),
        "model_sha256":hashlib.sha256(sources[1].read_bytes()).hexdigest(),
    }
    destination.mkdir(parents=True,mode=0o700)
    (destination/"compat.json").write_text(json.dumps({
        "schema":SCHEMA,"target":"cerato-network-web-8787",
        "from_versions":from_versions
    },sort_keys=True)+"\n",encoding="utf8")
    (destination/"routed-ui.json").write_text(
        json.dumps(manifest,sort_keys=True)+"\n",encoding="utf8")
    return {"schema":SCHEMA,"network_modified":False,
            "backend_in_archive":False,"frontend_in_archive":False,
            "files":["compat.json","routed-ui.json"]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--patch",type=Path,required=True)
    p.add_argument("--model",type=Path,required=True)
    p.add_argument("--destination",type=Path,required=True)
    p.add_argument("--from-version",action="append",required=True)
    args=p.parse_args()
    try:
        print(json.dumps(compose(args.patch,args.model,args.destination,
                                 args.from_version),sort_keys=True))
    except (RoutedReleaseError,ValueError,OSError,SyntaxError) as exc:
        p.error(str(exc))

if __name__=="__main__":
    main()

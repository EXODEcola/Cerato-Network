#!/usr/bin/env python3
"""Calculate the next immutable GitHub-only dev prerelease.

Development artifacts are unsigned source previews, NOT Cerato Web updates.
Only signed beta/stable releases are eligible for the OVH updater.
"""
from __future__ import annotations
import argparse
import json
import re
from typing import Any

RELEASE=re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(dev|beta|rc)\.([1-9]\d*))?$")

class DevReleaseError(ValueError):
    pass

def next_dev_version(entries: list[dict[str,Any]]) -> str:
    if not isinstance(entries,list) or len(entries)>1000:
        raise DevReleaseError("Liste des releases invalide")
    found=[]
    for item in entries:
        if not isinstance(item,dict) or not isinstance(item.get("tagName"),str):
            raise DevReleaseError("Entrée GitHub invalide")
        if item.get("isDraft",False):
            continue
        m=RELEASE.fullmatch(item["tagName"])
        if not m:
            # Tags that are not Cerato semver releases are not version anchors.
            continue
        core=tuple(int(x) for x in m.group(1,2,3))
        found.append((core,m.group(4),int(m.group(5) or 0)))
    approved=[core for core,kind,_ in found if kind!="dev"]
    if approved:
        base=max(approved)
        baseline=(base[0],base[1],base[2]+1)
    else:
        baseline=(0,1,0)
    higher_dev=[core for core,kind,_ in found if kind=="dev" and core>=baseline]
    next_core=max([baseline]+higher_dev)
    last=max([n for core,kind,n in found
              if core==next_core and kind=="dev"]+[0])
    if last>=1_000_000:
        raise DevReleaseError("Trop de versions de développement")
    return "v%d.%d.%d-dev.%d" % (*next_core,last+1)

def main():
    parser=argparse.ArgumentParser(description="Next Cerato Network GitHub-only dev release")
    parser.add_argument("--tags-json",required=True,
                        help="gh release list --json tagName,isDraft")
    args=parser.parse_args()
    with open(args.tags_json,encoding="utf8") as f:
        entries=json.load(f)
    print(next_dev_version(entries))

if __name__=="__main__":
    main()

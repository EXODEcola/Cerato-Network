#!/usr/bin/env python3
"""Validate an explicit, reviewed, signed-beta publication request.

No signing keys here. The protected signer rechecks and signs the result.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

TAG=re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(beta|rc)\.([1-9]\d*))?$")
BETA=re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-beta\.([1-9]\d*)$")

class BetaRequestError(ValueError):
    pass

def _order(value):
    match=TAG.fullmatch(value)
    if not match:
        raise BetaRequestError("Version source invalide")
    major,minor,patch=(int(x) for x in match.group(1,2,3))
    kind=match.group(4)
    rank={"beta":0,"rc":1,None:2}[kind]
    iteration=int(match.group(5) or 0)
    return major,minor,patch,rank,iteration

def validate(item):
    fields={"schema","version","from_version","channel","release_kind"}
    if not isinstance(item,dict) or set(item)!=fields:
        raise BetaRequestError("Structure de la demande invalide")
    if (item["schema"]!="cerato-beta-publication-request-v1" or
            item["channel"]!="beta" or item["release_kind"] not in ("routed-ui","nat-ui")):
        raise BetaRequestError("Canal ou contenu non approuvé")
    version=item["version"]
    baseline=item["from_version"]
    if (not isinstance(version,str) or not BETA.fullmatch(version)
            or not isinstance(baseline,str)):
        raise BetaRequestError("Version bêta invalide")
    if _order(version)<=_order(baseline):
        raise BetaRequestError("Release non supérieure à la version installée")
    return {"version":version,"channel":"beta","release_kind":item["release_kind"],
            "from_version":baseline}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--request",type=Path,required=True)
    args=parser.parse_args()
    request=args.request
    if request.is_symlink() or not request.is_file() or not 0<request.stat().st_size<=4096:
        parser.error("Fichier de demande absent ou invalide")
    try:
        values=validate(json.loads(request.read_text(encoding="utf8")))
    except (ValueError,TypeError,BetaRequestError) as exc:
        parser.error(str(exc))
    for key,value in values.items():
        print(key+"="+value)

if __name__=="__main__":
    main()

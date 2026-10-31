#!/usr/bin/env python3
"""Read public GitHub release assets, verify pinned Ed25519, publish to OVH.

No GitHub token, private signing key or direct Build access is required.
All untrusted files are bounded and verified before Nginx can serve them.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))

from publish_signed_release import publish, _trusted, PUBLIC_ROOT, TRUST_CONFIG
from remote import _parse_version, CHANNELS

REPO="EXODEcola/Cerato-Network"
RELEASES_API="https://api.github.com/repos/"+REPO+"/releases?per_page=20"
ASSETS=("manifest.json","manifest.sig","cerato-network-release.zip")
MAX={"manifest.json":32768,"manifest.sig":256,
     "cerato-network-release.zip":32_000_000,
     "beta.json":4096,"beta.sig":256,"stable.json":4096,"stable.sig":256,
     "release-verification.pub":4096}
HOSTS={"api.github.com","github.com","release-assets.githubusercontent.com",
       "objects.githubusercontent.com"}


class MirrorError(ValueError):
    pass


class RestrictedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlsplit(newurl)
        if (parsed.scheme!="https" or parsed.hostname not in HOSTS or
                parsed.port not in (None,443) or parsed.username or parsed.password):
            raise MirrorError("Redirection GitHub non approuvée")
        return super().redirect_request(request,fp,code,msg,headers,newurl)


def _get(url,limit):
    parts=urllib.parse.urlsplit(url)
    if (parts.scheme!="https" or parts.hostname not in HOSTS or
            parts.port not in (None,443) or parts.username or parts.password):
        raise MirrorError("URL non autorisée")
    req=urllib.request.Request(url,headers={"User-Agent":"CeratoNetworkReleaseMirror/1",
                                           "Accept":"application/vnd.github+json"})
    opener=urllib.request.build_opener(RestrictedRedirects())
    with opener.open(req,timeout=15) as response:
        data=response.read(limit+1)
    if not 0<len(data)<=limit:
        raise MirrorError("Fichier GitHub vide ou trop volumineux")
    return data


def discover(channel,*,get=_get):
    if channel not in CHANNELS:
        raise MirrorError("Canal non approuvé")
    listing=json.loads(get(RELEASES_API,500_000))
    if not isinstance(listing,list):
        raise MirrorError("Liste des releases non conforme")
    candidates=[]
    names=set(ASSETS)|{channel+".json",channel+".sig","release-verification.pub"}
    for release in listing:
        if (not isinstance(release,dict) or release.get("draft") or
                release.get("prerelease")!=(channel=="beta")):
            continue
        version=release.get("tag_name")
        try:
            rank=_parse_version(version)
        except (ValueError,TypeError):
            continue
        if channel=="beta" and "-beta." not in version:
            continue
        if channel=="stable" and "-" in version:
            continue
        assets=release.get("assets")
        if not isinstance(assets,list):
            continue
        byname={}
        for asset in assets:
            if isinstance(asset,dict) and asset.get("name") in names:
                name=asset["name"]
                expected="https://github.com/"+REPO+"/releases/download/"+version+"/"+name
                if asset.get("browser_download_url")!=expected or name in byname:
                    byname={}
                    break
                byname[name]=expected
        if set(byname)==names:
            candidates.append((rank,version,byname))
    if not candidates:
        return None
    return max(candidates,key=lambda x:x[0])[1:]


def synchronize(*,root=PUBLIC_ROOT,config=TRUST_CONFIG,get=_get,install=False):
    channel,key=_trusted(config)
    release=discover(channel,get=get)
    if not release:
        return {"state":"no_approved_github_release","installed":False,
                "channel":channel,"network_modified":False}
    version,urls=release
    with tempfile.TemporaryDirectory(prefix="cerato-gh-release-") as temp:
        folder=Path(temp)
        bundle=folder/"release"
        pointer=folder/"channels"
        bundle.mkdir(mode=0o700);pointer.mkdir(mode=0o700)
        for name in ASSETS:
            (bundle/name).write_bytes(get(urls[name],MAX[name]))
        for name in (channel+".json",channel+".sig"):
            (pointer/name).write_bytes(get(urls[name],MAX[name]))
        published_pub=get(urls["release-verification.pub"],4096)
        if key.read_bytes()!=published_pub:
            raise MirrorError("Clé publique GitHub différente de la clé épinglée sur OVH")
        result=publish(bundle,pointer,root=root,config=config,install=install)
    result["github_version"]=version
    result["network_modified"]=False
    return result


def main():
    parser=argparse.ArgumentParser(description="Synchroniser les releases GitHub Ed25519 vers HTTPS OVH")
    parser.add_argument("--install",action="store_true")
    args=parser.parse_args()
    if os.geteuid()!=0:
        parser.error("Exécution root du miroir uniquement")
    try:
        print(json.dumps(synchronize(install=args.install),sort_keys=True,
                         ensure_ascii=False,indent=2))
    except (MirrorError,OSError,ValueError,TypeError,KeyError,urllib.error.URLError) as exc:
        parser.error("Synchronisation refusée : "+str(exc))


if __name__=="__main__":
    main()

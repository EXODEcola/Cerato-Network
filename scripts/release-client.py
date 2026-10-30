#!/usr/bin/env python3
"""Manually verify/download a signed Cerato Network release without installing it.

Read-only HTTPS client. An independent, privileged service updater will be
needed later to activate a release and restart a running gateway/agent.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"updates"))
from remote import DistributionError, check_channel, download_channel


def main():
    parser=argparse.ArgumentParser(description="Cerato Network signed distribution client")
    parser.add_argument("action",choices=("check","download"))
    parser.add_argument("--base-url",required=True,
                        help="Operator-configured HTTPS release root, e.g. https://releases.example.org/cerato")
    parser.add_argument("--public-key",required=True,type=Path,
                        help="Locally pinned Ed25519 public verification key")
    parser.add_argument("--channel",choices=("stable","beta"),default="stable")
    parser.add_argument("--installed-version",default=None)
    parser.add_argument("--cache",type=Path,
                        help="Private 0700 release cache; required only for download")
    args=parser.parse_args()
    if args.action=="download" and args.cache is None:
        parser.error("--cache obligatoire pour download")
    try:
        if args.action=="check":
            result=check_channel(args.base_url,args.channel,args.public_key,
                                 installed_version=args.installed_version)
        else:
            result=download_channel(args.base_url,args.channel,args.public_key,args.cache,
                                    installed_version=args.installed_version)
    except (DistributionError,OSError,ValueError) as exc:
        parser.error("Distribution refusée : "+str(exc))
    print(json.dumps({"ok":True,**result},ensure_ascii=False,sort_keys=True))


if __name__=="__main__":
    main()

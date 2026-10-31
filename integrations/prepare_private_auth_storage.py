#!/usr/bin/env python3
"""Reserve the private native-account directory without activating authentication.

This deliberately never initializes AuthStore, creates a key/token/database,
changes systemd, nginx, WireGuard, NAT or an existing 8787 session.
No --path CLI override is accepted. The CLI is only for local RISE-1.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import stat
import sys

ROOT=Path("/var/lib")
STORE=ROOT/"cerato-network-auth"

class StoragePreparationError(ValueError):
    pass

def _stat_dir(path:Path, *, owner:int|None=None):
    try:
        info=path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) or (info.st_mode & 0o022):
        raise StoragePreparationError("Répertoire parent absent, symbolique ou accessible en écriture")
    if owner is not None and info.st_uid!=owner:
        raise StoragePreparationError("Propriétaire du répertoire parent inattendu")
    return info

def provision(directory:Path,*,uid:int,gid:int,install:bool=False,
              require_root_parent:bool=False) -> dict:
    directory=Path(directory)
    if directory.name!="cerato-network-auth":
        raise StoragePreparationError("Nom du stockage non approuvé")
    parent=directory.parent
    _stat_dir(parent,owner=0 if require_root_parent else None)
    if directory.exists() or directory.is_symlink():
        info=directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or
            info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=0o700):
            raise StoragePreparationError("Stockage existant non privé ou non conforme")
        return {"state":"private_directory_exists","created":False,
                "mode":"0700","owner_verified":True,
                "account_initialized":False,"web_service_modified":False,
                "network_modified":False}
    if not install:
        return {"state":"not_initialized","created":False,
                "expected_mode":"0700","account_initialized":False,
                "web_service_modified":False,"network_modified":False}
    if require_root_parent and os.geteuid()!=0:
        raise StoragePreparationError("sudo requis sur le serveur OVH")
    created=False
    try:
        os.mkdir(directory,mode=0o700)
        created=True
        if os.geteuid()==0:
            os.chown(directory,uid,gid)
        elif (uid,gid)!=(os.geteuid(),os.getegid()):
            raise StoragePreparationError("Droits système insuffisants")
        os.chmod(directory,0o700)
        info=directory.lstat()
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) != (uid,gid,0o700):
            raise StoragePreparationError("Propriétaire ou mode de stockage non conforme")
    except BaseException:
        if created:
            try:os.rmdir(directory)
            except OSError:pass
        raise
    return {"state":"private_directory_exists","created":True,
            "mode":"0700","owner_verified":True,
            "account_initialized":False,"web_service_modified":False,
            "network_modified":False}

def main():
    cli=argparse.ArgumentParser(description="Préparer uniquement le dossier privé des comptes natifs")
    group=cli.add_mutually_exclusive_group()
    group.add_argument("--check",action="store_true")
    group.add_argument("--install",action="store_true")
    args=cli.parse_args()
    if os.geteuid()!=0:
        cli.error("Exécuter avec sudo uniquement sur Cerato Network OVH")
    try:
        account=pwd.getpwnam("ceratonet")
        result=provision(STORE,uid=account.pw_uid,gid=account.pw_gid,
                         install=args.install,require_root_parent=True)
    except (StoragePreparationError,OSError,KeyError) as error:
        cli.error(str(error))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))

if __name__=="__main__":
    sys.exit(main())

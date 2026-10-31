#!/usr/bin/env python3
"""Conservative same-IP HTTPS release-location installer for RISE-1.

Preflight will not modify the server. Installation requires explicit --install
and a verified certificate for the IP. Only a single, exact vhost may be
changed. This does NOT create or sign any release or touch the auth backend.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HOST="51.210.223.57"
SNIPPET_PATH=Path("/etc/nginx/snippets/cerato-releases.conf")
MARKER="include /etc/nginx/snippets/cerato-releases.conf;"
ROOT=Path(__file__).resolve().parents[1]
SNIPPET=ROOT/"deploy/releases.same-host-location.conf"
SCOPES=("/etc/nginx/sites-enabled","/etc/nginx/conf.d")
MAX_SIZE=300_000
CERT_REQUIRED=True


class ProvisionError(ValueError):
    pass


def _run(*args, timeout=10):
    completed=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             text=True,timeout=timeout,check=False)
    if completed.returncode:
        raise ProvisionError("Vérification système échouée : "+args[0])
    return completed.stdout


def check_tls(host=HOST, *, port=443, connect_to=None):
    """Verify standard trust chain AND IP SAN against the requested IP."""
    if not isinstance(host,str):
        raise ProvisionError("IP HTTPS invalide")
    target=connect_to or host
    try:
        context=ssl.create_default_context()
        with socket.create_connection((target,port),timeout=5) as sock:
            with context.wrap_socket(sock,server_hostname=host) as tls:
                tls.getpeercert()
                protocol=tls.version()
    except (ssl.SSLError,OSError,TimeoutError) as exc:
        raise ProvisionError("HTTPS non vérifiable pour l'adresse IP ; "
                             "un certificat public avec SAN IP est requis") from exc
    return {"trusted_ip_certificate":True,"tls_protocol":protocol}


def _masked(source):
    """Ignore #comments and string contents while preserving offsets."""
    out=list(source)
    quote=None
    escaped=False
    comment=False
    for i,char in enumerate(source):
        if comment:
            if char=="\n":comment=False
            else:out[i]=" "
            continue
        if quote:
            out[i]=" "
            if escaped:escaped=False
            elif char=="\\":escaped=True
            elif char==quote:quote=None
            continue
        if char=="#":
            out[i]=" ";comment=True
        elif char in ("'",'"'):
            out[i]=" ";quote=char
    return "".join(out)


def _blocks(source):
    """Extract the exact span of complete server{} blocks, including nested locations."""
    masked=_masked(source)
    for match in re.finditer(r"\bserver\s*\{",masked):
        opening=masked.index("{",match.start(),match.end())
        depth=1
        i=opening+1
        while i<len(masked) and depth:
            if masked[i]=="{":depth+=1
            elif masked[i]=="}":depth-=1
            i+=1
        if depth:
            raise ProvisionError("Bloc Nginx non terminé")
        yield match.start(),i,opening


def _eligible(source):
    """Match an explicit 443 IP server, NOT a catch-all/default vhost."""
    masked=_masked(source)
    found=[]
    for start,end,opening in _blocks(source):
        header=masked[opening+1:end-1]
        # Include only directives at server's immediate scope.
        direct=[]
        depth=0
        for line in header.splitlines():
            level_line=line
            # Skip nested blocks, including nested locations.
            if depth==0:
                direct.append(level_line[:level_line.find("{")] if "{" in level_line else level_line)
            depth+=level_line.count("{")-level_line.count("}")
        directives="\n".join(direct)
        listens=re.findall(r"(?:^|;)\s*listen\s+([^;]+);",directives,re.M)
        names=re.findall(r"(?:^|;)\s*server_name\s+([^;]+);",directives,re.M)
        has443=any(re.search(r"(?<!\d)443(?!\d)",x) for x in listens)
        exact=any(HOST in x.split() for x in names)
        if has443 and exact:
            found.append((start,end,opening))
    return found


def discover(candidates=None, *, trusted_root=Path('/etc/nginx')):
    if candidates is None:
        candidates=[]
        for location in SCOPES:
            directory=Path(location)
            if directory.is_dir():
                candidates.extend(sorted(x for x in directory.iterdir() if x.is_file() or x.is_symlink()))
        # nginx.conf may itself define the only HTTPS server
        candidates.append(Path("/etc/nginx/nginx.conf"))
    matches=[]
    seen=set()
    for path in candidates:
        try:
            real=Path(path).resolve(strict=True)
            if real in seen:continue
            seen.add(real)
            if not real.is_file() or real.stat().st_size>MAX_SIZE:
                continue
            # Only amend nginx config files; refuse arbitrary paths in live.
            text=real.read_text(encoding="utf8")
        except (OSError,UnicodeError):
            continue
        for start,end,brace in _eligible(text):
            matches.append((real,text,start,end,brace))
    if len(matches)!=1:
        raise ProvisionError("Le bloc HTTPS de cette IP est ambigu ou introuvable : "
                             "aucune modification Nginx. Revue manuelle requise.")
    real,text,start,end,brace=matches[0]
    if MARKER in text or "/cerato-releases/" in text[start:end]:
        raise ProvisionError("Emplacement de distribution déjà présent, "
                             "configuration inchangée.")
    if real.is_symlink() or trusted_root.resolve() not in real.parents:
        raise ProvisionError("Fichier de configuration non approuvé")
    return real,text,end-1


def generate(text,closing):
    return text[:closing] + "    # Public signed files only; no change to /api or HTTP Basic elsewhere.\n    " + MARKER + "\n" + text[closing:]


def preflight(*,candidates=None,verify_tls=True,trusted_root=Path('/etc/nginx')):
    _run("nginx","-t")
    if verify_tls:
        tls=check_tls()
    else:
        tls={"trusted_ip_certificate":False}
    file,original,index=discover(candidates,trusted_root=trusted_root)
    snippet=SNIPPET.read_text(encoding="utf8")
    required=("location ^~ /cerato-releases/","auth_basic off;",
              "limit_except GET HEAD","root /srv/cerato-releases/public;")
    if any(x not in snippet for x in required):
        raise ProvisionError("Emplacement de distribution incomplet")
    root=Path("/srv/cerato-releases/public/cerato-releases")
    if not root.is_dir() or root.is_symlink():
        if candidates is None:
            raise ProvisionError("Répertoire de releases non préparé")
    return {"file":file,"original":original,"new":generate(original,index),
            "snippet":snippet,"tls":tls}


def install(plan):
    if os.geteuid()!=0:
        raise ProvisionError("Installation réservée à root")
    conf=plan["file"]
    if conf.read_text(encoding="utf8")!=plan["original"]:
        raise ProvisionError("La configuration Nginx a changé depuis le précontrôle")
    if SNIPPET_PATH.exists() or SNIPPET_PATH.is_symlink():
        raise ProvisionError("Le snippet existe déjà : installation interdite")
    if not SNIPPET_PATH.parent.is_dir():
        raise ProvisionError("Dossier /etc/nginx/snippets manquant")
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot=Path("/var/backups/cerato-network-inplace/nginx-releases")/stamp
    snapshot.mkdir(parents=True,mode=0o700,exist_ok=False)
    copy=snapshot/"vhost.conf"
    shutil.copy2(conf,copy)
    created=False
    updated=False
    try:
        SNIPPET_PATH.write_text(plan["snippet"],encoding="utf8")
        os.chmod(SNIPPET_PATH,0o644)
        created=True
        # Same directory atomic replacement, preserving original metadata.
        fd,name=tempfile.mkstemp(prefix=".cerato-release-",dir=conf.parent)
        try:
            os.fchmod(fd,conf.stat().st_mode & 0o777)
            with os.fdopen(fd,"w",encoding="utf8") as stream:
                stream.write(plan["new"])
                stream.flush();os.fsync(stream.fileno())
            os.replace(name,conf)
            updated=True
        finally:
            Path(name).unlink(missing_ok=True)
        _run("nginx","-t")
        _run("systemctl","reload","nginx")
    except BaseException:
        if updated:
            shutil.copy2(copy,conf)
        if created:
            SNIPPET_PATH.unlink(missing_ok=True)
        # Validate restored config before reloading; never change WireGuard.
        try:
            _run("nginx","-t")
            _run("systemctl","reload","nginx")
        except (OSError,ProvisionError,subprocess.TimeoutExpired):
            pass
        raise
    return str(snapshot)


def main():
    parser=argparse.ArgumentParser(description="Cerato HTTPS signed-release Nginx location")
    parser.add_argument("--install",action="store_true")
    args=parser.parse_args()
    try:
        plan=preflight()
        result={
            "format":"cerato-nginx-release-preflight-v1",
            "https_ip":HOST,
            "public_base":"https://"+HOST+"/cerato-releases/",
            "trusted_ip_certificate":plan["tls"]["trusted_ip_certificate"],
            "selected_vhosts":1,
            "config_modified":False,
            "signed_release_published":False,
            "signing_key_created":False,
        }
        if args.install:
            result["backup"]=install(plan)
            result["config_modified"]=True
        print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    except (OSError,ValueError,UnicodeError,ssl.SSLError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()

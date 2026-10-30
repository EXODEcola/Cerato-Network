"""Read-only HTTPS distribution client for signed Cerato Network releases.

No service restart, shell execution, networking changes or automatic install.
Only a preconfigured base URL is used. Every channel pointer, manifest and
archive is verified with a pinned public signing key.

URL layout:
    <base>/channels/stable.json + stable.sig
    <base>/channels/beta.json   + beta.sig
    <base>/releases/vX.Y.Z/manifest.json, manifest.sig, cerato-network-release.zip
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from build_release import (PackageError, canonical_json, validate_archive,
                           verify as verify_bundle, verify_signature)

VERSION=re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-(beta|rc)\.(\d+))?$")
HEX_SHA=re.compile(r"^[a-f0-9]{64}$")
CHANNELS={"stable","beta"}
MAX_MANIFEST=32768
MAX_INDEX=4096
MAX_SIG=256
MAX_ZIP=32_000_000


class DistributionError(Exception):
    pass


def _parse_version(version: str):
    if not isinstance(version,str):
        raise DistributionError("Version invalide")
    m=VERSION.fullmatch(version)
    if not m:
        raise DistributionError("Version invalide")
    major, minor, patch, prerelease, number=m.groups()
    # Stable ranks after all pre-releases of the same version.
    return (int(major), int(minor), int(patch),
            2 if prerelease is None else (1 if prerelease=="rc" else 0),
            int(number) if number is not None else 0)


def _base(url: str) -> str:
    if not isinstance(url,str) or len(url)>1024 or any(ord(c)<32 for c in url):
        raise DistributionError("Adresse de distribution invalide")
    try:
        parsed=urllib.parse.urlsplit(url)
        port=parsed.port
    except ValueError as exc:
        raise DistributionError("Adresse HTTPS mal formée") from exc
    if (parsed.scheme!="https" or not parsed.hostname or parsed.username is not None or
        parsed.password is not None or parsed.query or parsed.fragment or
        port not in (None,443) or "%2f" in parsed.path.lower() or
        ".." in parsed.path.split("/") or "\\" in parsed.path):
        raise DistributionError("Distribution HTTPS invalide")
    if parsed.path and not parsed.path.startswith("/"):
        raise DistributionError("Chemin de distribution invalide")
    # Host and path are configured by the service operator; no URL supplied by
    # an HTTP account can become a download destination.
    return url.rstrip("/")+"/"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise DistributionError("Redirection HTTPS de release interdite")


def _get(url: str, max_bytes: int, transport=None) -> bytes:
    request=urllib.request.Request(url,headers={
        "User-Agent":"Cerato-Network-Update-Check/0.1",
        "Accept":"application/octet-stream",
    },method="GET")
    try:
        if transport is None:
            opener=urllib.request.build_opener(_NoRedirect())
            response=opener.open(request,timeout=12)
        else:
            response=transport(request,timeout=12)
        with response:
            if getattr(response,"status",None)!=200 or response.geturl()!=url:
                raise DistributionError("Réponse HTTP inattendue")
            length=response.headers.get("Content-Length","")
            if length:
                try:
                    expected=int(length)
                except ValueError as exc:
                    raise DistributionError("Taille HTTP invalide") from exc
                if expected<1 or expected>max_bytes:
                    raise DistributionError("Fichier distant hors limites")
            blob=bytearray()
            while len(blob)<=max_bytes:
                chunk=response.read(min(65536,max_bytes+1-len(blob)))
                if not chunk:
                    break
                blob.extend(chunk)
            if not blob or len(blob)>max_bytes:
                raise DistributionError("Fichier distant vide ou trop volumineux")
            return bytes(blob)
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        raise DistributionError("Téléchargement HTTPS impossible") from exc


def _channel_index(base_url: str, channel: str, key: Path, transport=None, now=None):
    if channel not in CHANNELS:
        raise DistributionError("Canal invalide")
    base=_base(base_url)
    raw=_get(base+"channels/"+channel+".json",MAX_INDEX,transport)
    sig=_get(base+"channels/"+channel+".sig",MAX_SIG,transport)
    try:
        verify_signature(raw,sig,Path(key))
        payload=json.loads(raw)
        if not isinstance(payload,dict) or canonical_json(payload)!=raw:
            raise DistributionError("Index non canonique")
        if (payload.get("schema")!=1 or payload.get("product")!="cerato-network" or
            payload.get("channel")!=channel or
            not isinstance(payload.get("manifest_sha256"),str) or
            not HEX_SHA.fullmatch(payload["manifest_sha256"])):
            raise DistributionError("Index de version invalide")
        version=payload.get("version")
        _parse_version(version)
        if channel=="stable" and "-" in version:
            raise DistributionError("Version bêta interdite sur stable")
        issued=payload.get("issued_at")
        expires=payload.get("expires_at")
        when=int(time.time()) if now is None else int(now)
        if (type(issued) is not int or type(expires) is not int or
            expires<=issued or expires-issued>7*86400 or
            issued>when+300 or expires<=when):
            raise DistributionError("Index expiré ou daté incorrectement")
        return payload
    except (PackageError,ValueError,TypeError,KeyError,OSError,subprocess.TimeoutExpired) as exc:
        raise DistributionError("Index signé invalide") from exc


def check_channel(base_url: str, channel: str, key: Path, *,
                  installed_version: str | None=None, transport=None,
                  now=None) -> dict:
    pointer=_channel_index(base_url,channel,key,transport,now)
    newest=pointer["version"]
    newer=True if installed_version is None else _parse_version(newest)>_parse_version(installed_version)
    return {"channel":channel,"version":newest,"installed_version":installed_version,
            "update_available":newer,"signed":True,"expires_at":pointer["expires_at"]}


@contextmanager
def _private_lock(root: Path):
    root=Path(root)
    if root.is_symlink() or root.exists() and not root.is_dir():
        raise DistributionError("Cache local invalide")
    root.mkdir(parents=True,mode=0o700,exist_ok=True)
    info=root.stat()
    if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
        raise DistributionError("Cache local non privé")
    lock=root/".download.lock"
    if lock.is_symlink():
        raise DistributionError("Verrou symbolique refusé")
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield root
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def download_channel(base_url: str, channel: str, key: Path, cache: Path, *,
                     installed_version: str | None=None, transport=None,
                     now=None) -> dict:
    """Download, authenticate and cache the latest signed release, NEVER run it.

    Uses the same signed key as the gateway; all paths are derived from a
    verified version, never from a remote arbitrary URL or user-supplied path.
    """
    index=_channel_index(base_url,channel,key,transport,now)
    version=index["version"]
    if installed_version is not None and _parse_version(version)<=_parse_version(installed_version):
        raise DistributionError("Aucune version plus récente autorisée")
    url=_base(base_url)+"releases/"+version+"/"
    manifest=_get(url+"manifest.json",MAX_MANIFEST,transport)
    signature=_get(url+"manifest.sig",MAX_SIG,transport)
    if hashlib.sha256(manifest).hexdigest()!=index["manifest_sha256"]:
        raise DistributionError("Manifest ne correspond pas à l'index signé")
    try:
        verify_signature(manifest,signature,Path(key))
        info=json.loads(manifest)
        if not isinstance(info,dict) or canonical_json(info)!=manifest:
            raise DistributionError("Manifest non canonique")
        if (info.get("schema")!=1 or info.get("product")!="cerato-network" or
            info.get("version")!=version or
            info.get("signature_algorithm")!="ed25519" or
            info.get("artifact")!="cerato-network-release.zip" or
            not isinstance(info.get("sha256"),str) or
            not HEX_SHA.fullmatch(info["sha256"]) or
            type(info.get("size")) is not int or
            not 0<info["size"]<=MAX_ZIP):
            raise DistributionError("Manifest incompatible")
    except (PackageError,ValueError,TypeError) as exc:
        raise DistributionError("Manifest invalide ou signature refusée") from exc

    blob=_get(url+"cerato-network-release.zip",MAX_ZIP,transport)
    if len(blob)!=info["size"] or hashlib.sha256(blob).hexdigest()!=info["sha256"]:
        raise DistributionError("Archive téléchargée altérée")
    try:
        validate_archive(blob)
    except (PackageError,zipfile.BadZipFile) as exc:
        raise DistributionError("Archive ZIP invalide") from exc

    with _private_lock(cache) as root:
        target=root/version
        if target.exists() or target.is_symlink():
            try:
                verified=verify_bundle(target,Path(key))
            except (OSError,PackageError,ValueError,zipfile.BadZipFile) as exc:
                raise DistributionError("Release existante non valide") from exc
            if verified["sha256"]!=info["sha256"]:
                raise DistributionError("Conflit sur la version existante")
            return {"version":version,"cached":True,"downloaded":False,"path":str(target)}
        temp=Path(tempfile.mkdtemp(prefix=".incoming-",dir=root))
        try:
            for name,data in (("manifest.json",manifest),("manifest.sig",signature),
                              ("cerato-network-release.zip",blob)):
                file=temp/name
                fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,"wb") as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
            verify_bundle(temp,Path(key))
            os.rename(temp,target)
        except BaseException:
            import shutil
            shutil.rmtree(temp,ignore_errors=True)
            raise
    return {"version":version,"cached":True,"downloaded":True,"path":str(target)}

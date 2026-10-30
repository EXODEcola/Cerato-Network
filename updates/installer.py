"""Verified immutable release staging for Cerato Network.

Runs as an unprivileged, dedicated service account, on an owned 0700 root.
Never touches WireGuard, firewall, OS services or /etc. A separate operator/
controller must perform health checks and service restarts before production.
"""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from contextlib import contextmanager

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE/"tools"))
from build_release import verify, PackageError, validate_archive

VERSION=re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-(?:beta|rc)\.[0-9]+)?$")
MARKER=".cerato-release.json"


class StageError(Exception):
    pass


def _strict_root(root: Path) -> Path:
    root=Path(root)
    if root.is_symlink() or root.exists() and not root.is_dir():
        raise StageError("Répertoire de déploiement invalide")
    root.mkdir(parents=True,mode=0o700,exist_ok=True)
    if root.stat().st_mode & 0o077:
        raise StageError("Répertoire de déploiement doit être privé (0700)")
    if root.stat().st_uid != os.geteuid():
        raise StageError("Répertoire de déploiement doit appartenir au processus")
    return root.resolve(strict=True)


@contextmanager
def _lock(root: Path):
    lock_path=root/".release-lock"
    if lock_path.is_symlink():
        raise StageError("Verrou symbolique refusé")
    fd=os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def _atomic_json(root: Path, name: str, value: dict):
    data=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode("utf8")
    fd,path=tempfile.mkstemp(prefix=".new-state-",dir=str(root))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path,root/name)
    finally:
        if os.path.lexists(path):
            os.unlink(path)


def _load_release(root: Path, version: str) -> Path:
    if not isinstance(version,str) or not VERSION.fullmatch(version):
        raise StageError("Version invalide")
    dest=root/"releases"/version
    if dest.is_symlink() or not dest.is_dir():
        raise StageError("Version non préparée")
    marker=dest/MARKER
    if marker.is_symlink() or not marker.is_file():
        raise StageError("Marqueur de release manquant")
    try:
        data=json.loads(marker.read_text(encoding="utf8"))
        if data.get("version") != version or not re.fullmatch("[0-9a-f]{64}",str(data.get("sha256"))):
            raise ValueError()
    except (OSError,ValueError):
        raise StageError("Marqueur de release invalide")
    return dest


def stage(bundle: Path, public_key: Path, root: Path) -> dict:
    """Verify signature & ZIP, extract privately, and commit immutable version.

    Never calls systemctl, nft, wg, apt, sudo or a shell.
    """
    root=_strict_root(root)
    bundle=Path(bundle)
    public_key=Path(public_key)
    if bundle.is_symlink() or public_key.is_symlink():
        raise StageError("Lien symbolique de distribution interdit")
    try:
        manifest=verify(bundle,public_key)
    except (PackageError,ValueError,RuntimeError,OSError,zipfile.BadZipFile) as exc:
        raise StageError("Release non authentifiée ou archive invalide") from exc
    version=manifest["version"]
    with _lock(root):
        releases=root/"releases"
        if releases.is_symlink():
            raise StageError("Répertoire de releases symbolique interdit")
        releases.mkdir(mode=0o700,exist_ok=True)
        releases=os.path.realpath(releases)
        target=Path(releases)/version
        if target.exists() or target.is_symlink():
            existing=_load_release(root,version)
            marker=json.loads((existing/MARKER).read_text(encoding="utf8"))
            if marker["sha256"]!=manifest["sha256"]:
                raise StageError("Version existante différente : refus de remplacement")
            return {"version":version,"sha256":manifest["sha256"],"staged":True,"already_present":True}
        tmp=Path(tempfile.mkdtemp(prefix=".incoming-",dir=releases))
        try:
            archive=(bundle/manifest["artifact"]).read_bytes()
            # Verify the *same bytes* that we extract, even if an attacker
            # swaps the distribution file after the initial verify().
            if (len(archive) != manifest["size"] or
                hashlib.sha256(archive).hexdigest() != manifest["sha256"]):
                raise StageError("Archive modifiée après vérification")
            validate_archive(archive)
            with zipfile.ZipFile(io.BytesIO(archive),"r") as z:
                for item in z.infolist():
                    rel=Path(*item.filename.split("/")[1:])
                    if not rel.parts:
                        raise StageError("Chemin vide dans l'archive")
                    final=tmp/rel
                    final.parent.mkdir(parents=True,exist_ok=True)
                    # Exclusive/no-follow makes extraction resistant to local
                    # symlink injection in the private staging directory.
                    fd=os.open(final,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,"wb") as output, z.open(item,"r") as src:
                        shutil.copyfileobj(src,output,length=65536)
            _atomic_json(tmp,MARKER,{"version":version,"sha256":manifest["sha256"]})
            os.rename(tmp,target)
        except BaseException:
            shutil.rmtree(tmp,ignore_errors=True)
            raise
        return {"version":version,"sha256":manifest["sha256"],"staged":True,"already_present":False}


def _current(root: Path) -> str | None:
    ref=root/"current"
    if not ref.is_symlink():
        if ref.exists():
            raise StageError("Chemin current non symbolique")
        return None
    target=os.readlink(ref)
    if not target.startswith("releases/"):
        raise StageError("Lien current hors de l'arbre des releases")
    version=target.removeprefix("releases/")
    if not VERSION.fullmatch(version):
        raise StageError("Lien current invalide")
    _load_release(root,version)
    return version


def _switch(root: Path, version: str | None):
    target=root/"current"
    if version is None:
        if target.is_symlink():
            target.unlink()
        return
    _load_release(root,version)
    tmp=root/(".next-"+version)
    if tmp.exists() or tmp.is_symlink():
        raise StageError("Lien temporaire déjà existant")
    tmp.symlink_to("releases/"+version)
    try:
        os.replace(tmp,target)
    finally:
        if tmp.is_symlink():
            tmp.unlink()


def activate(root: Path, version: str, healthcheck) -> dict:
    """Switch only after caller supplies a *trusted* local healthcheck function.

    The callback must verify the service is healthy, independent of browser
    input. On failure revert current symlink to the previous known release.
    """
    root=_strict_root(root)
    if not callable(healthcheck):
        raise StageError("Contrôle de santé obligatoire")
    with _lock(root):
        _load_release(root,version)
        old=_current(root)
        if old==version:
            return {"version":version,"previous":old,"changed":False}
        _switch(root,version)
        try:
            if healthcheck(root/"current") is not True:
                raise StageError("Contrôle de santé négatif")
        except BaseException:
            _switch(root,old)
            raise
        _atomic_json(root,"previous.json",{"previous":old,"active":version})
        return {"version":version,"previous":old,"changed":True}


def rollback(root: Path, healthcheck) -> dict:
    root=_strict_root(root)
    if not callable(healthcheck):
        raise StageError("Contrôle de santé obligatoire")
    with _lock(root):
        file=root/"previous.json"
        if file.is_symlink() or not file.is_file():
            raise StageError("Aucun retour arrière disponible")
        data=json.loads(file.read_text(encoding="utf8"))
        current=_current(root)
        if data.get("active") != current or not data.get("previous"):
            raise StageError("État de restauration incohérent")
        previous=data["previous"]
        _load_release(root,previous)
        _switch(root,previous)
        try:
            if healthcheck(root/"current") is not True:
                raise StageError("Ancienne version non fonctionnelle")
        except BaseException:
            _switch(root,current)
            raise
        _atomic_json(root,"previous.json",{"previous":current,"active":previous})
        return {"version":previous,"restored_from":current}

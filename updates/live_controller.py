#!/usr/bin/env python3
"""Fixed-command updater for the *existing* Cerato Network Web service (8787).

Only an operator-configured HTTPS source and locally pinned Ed25519 key are
accepted. Browser users cannot supply URLs, local paths or shell commands.
The signed archive MUST contain a compatible legacy-web overlay. No generic
source release may replace the functional RISE-1 network control plane.

Commands: status, check, apply. The controller changes only three root-owned
Web files and restarts cerato-network-web.service, never WireGuard, IPs, routes,
nftables, SSH, or ceratoctl.
"""
from __future__ import annotations
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/"tools"))
sys.path.insert(0,str(ROOT/"updates"))
from build_release import verify, PackageError
from remote import check_channel, download_channel, DistributionError, DistributionNotFound, _parse_version

SERVICE="cerato-network-web.service"
BASE=Path("/opt/cerato-network")
SETTING=Path("/etc/cerato-network/release-source.json")
STORE=Path("/var/lib/cerato-network-updates")
CACHE=STORE/"verified"
SNAPSHOTS=STORE/"snapshots"
STATE=STORE/"state.json"
LOCK=STORE/".update.lock"
ALLOWED={
    "backend/server.py":BASE/"backend/server.py",
    "web/app.js":BASE/"web/app.js",
    "web/style.css":BASE/"web/style.css",
}
OVERLAY="cerato-network/live-overlay/"
SCHEMA="cerato-network-legacy-web-overlay-v1"
VISUAL_SCHEMA="cerato-network-legacy-web-visual-v1"
VISUAL_FILES={"web/app.js","web/style.css"}
CSS_PATCH_SCHEMA="cerato-network-legacy-web-css-v1"
CSS_PATCH_FILES={"web/style.append.css"}
CSS_PATCH_MARKER=b"/* CERATO-NETWORK-SIGNED-CSS-V1 */"


class UpdateError(RuntimeError):
    pass


def _cmd(*args,timeout=25):
    try:
        result=subprocess.run(list(args),capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise UpdateError("Commande système indisponible") from exc
    if result.returncode:
        raise UpdateError("Échec de validation d'un service système")
    return result.stdout


def _settings():
    if SETTING.is_symlink() or not SETTING.is_file():
        raise UpdateError("Distribution de releases non configurée sur cette installation")
    if SETTING.stat().st_uid!=0 or SETTING.stat().st_mode & 0o077:
        raise UpdateError("Paramètres de distribution non privés")
    doc=json.loads(SETTING.read_text(encoding="utf8"))
    if not isinstance(doc,dict) or set(doc)!={"base_url","channel","public_key"}:
        raise UpdateError("Paramètres de distribution invalides")
    if doc["channel"] not in ("stable","beta","dev"):
        raise UpdateError("Canal de releases invalide")
    key=Path(doc["public_key"])
    if (key.is_symlink() or not key.is_file() or key.stat().st_uid!=0 or
        key.stat().st_mode & 0o022):
        raise UpdateError("Clé publique d'update non approuvée")
    # remote.py also enforces HTTPS, port 443, forbids redirects and validates
    # the signed channel/manifest/ZIP. There is no browser-origin override.
    return doc,key


def _state():
    if STATE.is_symlink():
        raise UpdateError("État des mises à jour symbolique interdit")
    if not STATE.exists():
        return {"installed_version":"v0.0.0","history":[],"state":"ready"}
    out=json.loads(STATE.read_text(encoding="utf8"))
    _parse_version(out["installed_version"])
    return out


def _save(data):
    STORE.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=".update-state-",dir=STORE)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf8") as stream:
            json.dump(data,stream,sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name,STATE)
    finally:
        Path(name).unlink(missing_ok=True)


def _candidate(state,key):
    version=state.get("available_version")
    if not version:
        return None
    _parse_version(version)
    path=CACHE/version
    if path.is_symlink() or not path.is_dir():
        return None
    try:
        manifest=verify(path,key)
    except (PackageError,OSError,ValueError,subprocess.TimeoutExpired):
        return None
    if manifest["version"]!=version or _parse_version(version)<=_parse_version(state["installed_version"]):
        return None
    _read_overlay(path,state["installed_version"],verify_only=True)
    return path


def _read_overlay(bundle,installed_version,verify_only=False):
    """Hard compatibility gate: never install a generic repo source package."""
    archive=bundle/"cerato-network-release.zip"
    with zipfile.ZipFile(archive,"r") as z:
        marker=OVERLAY+"compat.json"
        if marker not in z.namelist():
            raise UpdateError("Release non compatible avec le panneau RISE-1 actuel")
        spec=json.loads(z.read(marker))
        if (not isinstance(spec,dict) or
            spec.get("schema") not in (SCHEMA,VISUAL_SCHEMA,CSS_PATCH_SCHEMA) or
            spec.get("target")!="cerato-network-web-8787" or
            not isinstance(spec.get("from_versions"),list) or
            installed_version not in spec["from_versions"]):
            raise UpdateError("Migration de cette version non autorisée")
        required=(set(ALLOWED) if spec["schema"]==SCHEMA else
                  CSS_PATCH_FILES if spec["schema"]==CSS_PATCH_SCHEMA else VISUAL_FILES)
        # The only allowed update payloads are the known full legacy overlay or
        # a style+JS update. A visual refresh never redistributes server.py.
        found={name.removeprefix(OVERLAY) for name in z.namelist()
               if name.startswith(OVERLAY) and name!=marker}
        if found!=required:
            raise UpdateError("Contenu de release Web inattendu")
        for name in required:
            info=z.getinfo(OVERLAY+name)
            if info.file_size<=0 or info.file_size>2_000_000:
                raise UpdateError("Fichier de mise à jour hors limites")
        if spec["schema"]==CSS_PATCH_SCHEMA:
            patch=z.read(OVERLAY+"web/style.append.css")
            if (not patch.startswith(CSS_PATCH_MARKER) or
                    b"@import" in patch.lower() or b"url(" in patch.lower()):
                raise UpdateError("Correctif CSS signé non conforme")
            if verify_only:
                return None
            target=ALLOWED["web/style.css"]
            if target.is_symlink() or not target.is_file():
                raise UpdateError("CSS existant inconnu")
            existing=target.read_bytes()
            if len(existing)+len(patch)>2_000_000 or CSS_PATCH_MARKER in existing:
                raise UpdateError("Correctif CSS déjà présent ou trop volumineux")
            return {"web/style.css":existing.rstrip(b"\r\n")+b"\n"+patch+b"\n"}
        if verify_only:
            return None
        return {name:z.read(OVERLAY+name) for name in sorted(required)}


def _snapshot():
    SNAPSHOTS.mkdir(parents=True,mode=0o700,exist_ok=True)
    name=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())+"-"+str(os.getpid())
    folder=SNAPSHOTS/name
    folder.mkdir(mode=0o700)
    for rel,source in ALLOWED.items():
        if source.is_symlink() or not source.is_file():
            raise UpdateError("Fichier Web inattendu : "+rel)
        dest=folder/rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,dest,follow_symlinks=False)
    return folder


def _replace(files):
    if not isinstance(files,dict) or set(files) not in (set(ALLOWED),VISUAL_FILES,{"web/style.css"}):
        raise UpdateError("Liste de fichiers Web non autorisée")
    for rel in sorted(files):
        source=ALLOWED[rel]
        if source.is_symlink() or not source.is_file():
            raise UpdateError("Fichier Web inattendu : "+rel)
        fd,path=tempfile.mkstemp(prefix=".cerato-new-",dir=source.parent)
        try:
            os.fchmod(fd,0o644)
            with os.fdopen(fd,"wb") as out:
                out.write(files[rel])
                out.flush()
                os.fsync(out.fileno())
            os.replace(path,source)
        finally:
            Path(path).unlink(missing_ok=True)


def _controller_executable_ok(controller=Path("/usr/local/sbin/ceratoctl")):
    """Reject Web upgrades when the root network CLI is not executable Python.

    A broken direct entrypoint can leave the HTML Web process healthy while
    every authenticated API call fails. Never change networking here.
    """
    if controller.is_symlink() or not controller.is_file():
        return False
    try:
        with controller.open("rb") as stream:
            first=stream.readline(120)
        if not first.startswith(b"#!") or b"python" not in first.lower():
            return False
        response=_cmd(str(controller),"status",timeout=12)
        return isinstance(json.loads(response),dict)
    except (OSError,ValueError,UpdateError):
        return False


def _web_ok():
    try:
        _cmd("systemctl","is-active","--quiet",SERVICE,timeout=8)
        _cmd("curl","--fail","--silent","--show-error","--max-time","6",
             "http://127.0.0.1:8787/",timeout=8)
        return True
    except UpdateError:
        return False


# Critical invariant: runtime peer counters/handshakes are NOT configuration.
# Compare the persistent source of truth instead, before and after a Web update.
# A live handshake must never cause a false rollback.
NETWORK_CONFIG_FILES=(
    Path("/etc/cerato-network/config.json"),
    Path("/etc/wireguard/wg-cerato.conf"),
)


def _network_fingerprint():
    digest=hashlib.sha256()
    for path in NETWORK_CONFIG_FILES:
        if path.is_symlink() or not path.is_file():
            raise UpdateError("Configuration réseau absente ou symbolique")
        info=path.stat()
        if info.st_size<=0 or info.st_size>2_000_000:
            raise UpdateError("Taille de configuration réseau invalide")
        digest.update(str(path).encode("utf8"))
        digest.update(b"\\x00")
        digest.update(path.read_bytes())
        digest.update(b"\\x00")
    return digest.hexdigest()


def status():
    """Status never contacts the network nor treats unconfigured as signature failure."""
    state=_state()
    answer={"installed_version":state["installed_version"],
            "available_version":state.get("available_version"),
            "channel":None,
            "configured":False,
            "can_check":False,
            "installable":False,
            "status":state.get("state","ready"),
            "reason_code":state.get("reason_code","unknown"),
            "last_checked_at":state.get("last_checked_at"),
            "last_result":state.get("last_result",""),
            "history":state.get("history",[])[-8:]}
    try:
        config,key=_settings()
    except (UpdateError,OSError,ValueError,KeyError):
        answer["status"]="unconfigured"
        answer["reason_code"]="source_not_configured"
        answer["available_version"]=None
        answer["last_result"]="La source HTTPS de distribution signée n'est pas encore configurée sur cette passerelle."
        return answer
    answer["configured"]=True
    answer["can_check"]=True
    answer["channel"]=config["channel"]
    try:
        answer["installable"]=_candidate(state,key) is not None
    except (UpdateError,OSError,ValueError,zipfile.BadZipFile):
        answer["installable"]=False
    if state.get("available_version") and not answer["installable"]:
        answer["reason_code"]="release_not_compatible"
    elif answer["installable"]:
        answer["reason_code"]="release_ready"
    return answer


def check():
    state=_state()
    state["last_checked_at"]=int(time.time())
    # A missing source is an onboarding state, not a broken signature.
    try:
        config,key=_settings()
    except (UpdateError,OSError,ValueError,KeyError):
        state["available_version"]=None
        state["last_result"]="Distribution non configurée : source HTTPS et clé publique requises."
        state["state"]="unconfigured"
        state["reason_code"]="source_not_configured"
        _save(state)
        return status()
    try:
        # A signed channel can legitimately announce the same version as installed.
        try:
            latest=check_channel(config["base_url"],config["channel"],key,
                                 installed_version=state["installed_version"])
        except DistributionNotFound:
            # During the initial setup, no signed channel exists yet. A
            # missing channel is not evidence of a failed certificate/key.
            state["available_version"]=None
            state["state"]="waiting"
            state["reason_code"]="channel_not_published"
            state["last_result"]="Aucune release signée publiée sur ce canal pour le moment."
            _save(state)
            return status()
        if not latest["update_available"]:
            state["available_version"]=None
            state["state"]="current"
            state["reason_code"]="already_current"
            state["last_result"]="Le panneau est à jour sur le canal sélectionné."
            _save(state)
            return status()
        result=download_channel(config["base_url"],config["channel"],key,CACHE,
                                installed_version=state["installed_version"])
        state["available_version"]=result["version"]
        state["state"]="downloaded"
        # A cryptographically valid archive can still target a different
        # panel version. That is a normal incompatibility, not a broken TLS
        # provider or an invalid signature.
        try:
            candidate=_candidate(state,key)
        except (UpdateError,ValueError,KeyError,zipfile.BadZipFile):
            candidate=None
        if candidate is None:
            state["reason_code"]="release_not_compatible"
            state["last_result"]="Release authentifiée, mais incompatible avec ce panneau."
        else:
            state["reason_code"]="release_ready"
            state["last_result"]="Release signée, compatible et prête à installer."
    except (DistributionError,PackageError,UpdateError,OSError,ValueError,
            KeyError,zipfile.BadZipFile) as exc:
        # Never show the distribution URL, keys, raw TLS errors or filesystem paths.
        state["available_version"]=None
        state["state"]="check_failed"
        state["reason_code"]="release_check_failed"
        state["last_result"]="Impossible de valider la distribution signée. Consulter le journal."
    _save(state)
    return status()


def apply():
    if os.geteuid()!=0:
        raise UpdateError("Installation réservée au service système root")
    config,key=_settings()
    state=_state()
    bundle=_candidate(state,key)
    if bundle is None:
        raise UpdateError("Aucune release signée et compatible à installer")
    version=state["available_version"]
    files=_read_overlay(bundle,state["installed_version"])
    # Validate exact contents before changing anything.
    with tempfile.TemporaryDirectory(prefix="cerato-update-validate-") as folder:
        for name,data in files.items():
            dest=Path(folder)/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(data)
        if "backend/server.py" in files:
            _cmd(sys.executable,"-m","py_compile",str(Path(folder)/"backend/server.py"))
        if "web/app.js" in files:
            if not shutil.which("node"):
                raise UpdateError("Node.js requis pour la validation du JavaScript")
            _cmd("node","--check",str(Path(folder)/"web/app.js"))
    if not _controller_executable_ok():
        raise UpdateError("Contrôleur réseau Cerato invalide : mise à jour Web refusée, réparer ceratoctl")
    if not _web_ok():
        raise UpdateError("Le panneau existant est déjà en défaut")
    previous_network=_network_fingerprint()
    snap=_snapshot()
    state["state"]="installing"
    state["last_result"]="Installation en cours"
    _save(state)
    try:
        _replace(files)
        _cmd("systemctl","restart",SERVICE,timeout=20)
        for _ in range(6):
            if _web_ok():
                break
            time.sleep(1)
        if not _web_ok() or _network_fingerprint()!=previous_network:
            raise UpdateError("Contrôle de santé ou intégrité du réseau non conforme")
        state["installed_version"]=version
        state["available_version"]=None
        state["state"]="ready"
        state["last_result"]="Version "+version+" installée et vérifiée"
        state.setdefault("history",[]).append({
            "version":version,"snapshot":snap.name,"time":int(time.time()),
        })
        _save(state)
    except BaseException:
        try:
            previous={rel:(snap/rel).read_bytes() for rel in ALLOWED}
            _replace(previous)
            _cmd("systemctl","restart",SERVICE,timeout=20)
            state["state"]="failed"
            state["last_result"]="Échec : ancienne version restaurée"
        finally:
            _save(state)
        raise
    return status()


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Cerato Network trusted legacy Web updater")
    parser.add_argument("action",choices=("status","check","apply"))
    args=parser.parse_args()
    if os.geteuid()!=0:
        parser.error("Exécution sous l'identité root du service d'updates uniquement")
    STORE.mkdir(mode=0o700,parents=True,exist_ok=True)
    if STORE.is_symlink() or STORE.stat().st_mode & 0o077:
        parser.error("Dossier de mise à jour non privé")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        if args.action=="status":result=status()
        elif args.action=="check":result=check()
        else:result=apply()
        print(json.dumps(result,ensure_ascii=False))
    except (OSError,UpdateError,DistributionError,PackageError,
            ValueError,KeyError,zipfile.BadZipFile,subprocess.TimeoutExpired) as e:
        parser.error("Mise à jour refusée : "+str(e))
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


if __name__=="__main__":
    main()

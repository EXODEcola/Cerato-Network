#!/usr/bin/env python3
"""ONE-TIME activation of the existing RISE-1 *signed* Web update source.

This is an OVH-only operator tool. It never contacts Cerato Build and does not
alter the network, live Web files, Nginx or authentication. It cannot mint a
trusted signing identity or invent a signed release.

The command becomes operational when an independently approved public key
and the corresponding signed HTTPS release channel both exist.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from configure_live_release_source import provision,CONFIG

BASE_URL="https://51.210.223.57/cerato-releases"
CTL=Path("/usr/local/sbin/cerato-updatectl")
WEB=Path("/opt/cerato-network/web/app.js")
NGINX=Path("/etc/nginx/snippets/cerato-releases.conf")
NET=(Path("/etc/cerato-network/config.json"),
     Path("/etc/wireguard/wg-cerato.conf"))


class ActivationError(RuntimeError):
    pass


def _json_ctl(action,ctl=CTL):
    completed=subprocess.run([str(ctl),action],capture_output=True,text=True,
                             timeout=35,check=False)
    if completed.returncode:
        raise ActivationError("Moteur de mises à jour non opérationnel : "+action)
    try:
        data=json.loads(completed.stdout)
    except ValueError as exc:
        raise ActivationError("Réponse du moteur non exploitable") from exc
    if not isinstance(data,dict):
        raise ActivationError("Statut du moteur invalide")
    return data


def _network_snapshot(paths=NET):
    digest=hashlib.sha256()
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ActivationError("Fichiers de configuration réseau introuvables")
        digest.update(str(path).encode())
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def _prerequisites(*,ctl=CTL,web=WEB,nginx=NGINX):
    if os.geteuid()!=0:
        raise ActivationError("Contrôle réservé à sudo sur OVH RISE-1")
    if not ctl.is_file() or ctl.is_symlink() or not os.access(ctl,os.X_OK):
        raise ActivationError("Le moteur existant doit être installé en premier")
    if not web.is_file() or web.is_symlink():
        raise ActivationError("Interface RISE-1 introuvable")
    if not nginx.is_file() or nginx.is_symlink():
        raise ActivationError("Emplacement HTTPS signé Nginx non installé")
    if "location ^~ /cerato-releases/" not in nginx.read_text(encoding="utf8"):
        raise ActivationError("Emplacement HTTPS incorrect")
    return _json_ctl("status",ctl)


def _tls_probe(url=BASE_URL+"/channels/beta.json"):
    # HTTP 404 means the TLS identity was verified, but the signed channel
    # has not been published. Never bypass TLS or follow redirects.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            raise ActivationError("Redirection du canal interdite")
    opener=urllib.request.build_opener(NoRedirect)
    request=urllib.request.Request(url,headers={"User-Agent":"Cerato-Setup/1"},
                                   method="HEAD")
    try:
        with opener.open(request,timeout=8) as response:
            if response.status!=200:
                raise ActivationError("Réponse HTTPS de canal inattendue")
            return True
    except urllib.error.HTTPError as exc:
        if exc.code==404:
            return False
        raise ActivationError("Le canal HTTPS n'est pas disponible") from exc
    except urllib.error.URLError as exc:
        raise ActivationError("Certificat TLS ou connexion HTTPS invalide") from exc


def _start_periodic_checks():
    script=ROOT/"scripts/enable-live-update-check.timer.sh"
    if script.is_symlink() or not script.is_file():
        raise ActivationError("Service de surveillance signé introuvable")
    result=subprocess.run(["/bin/bash",str(script),"--install"],
                          capture_output=True,text=True,timeout=30,check=False)
    if result.returncode:
        raise ActivationError("Activation du contrôle périodique refusée : consulter journal système")


def activate(*,install=False,public_key=None,fingerprint=None,channel="beta"):
    before=_network_snapshot()
    existing=_prerequisites()
    if channel not in ("stable","beta"):
        raise ActivationError("Canal invalide")
    if bool(public_key) != bool(fingerprint):
        raise ActivationError("La clé publique et son empreinte doivent être fournies ensemble")
    if not existing.get("configured"):
        if not install:
            return {"status":"source_missing","configured":False,
                    "next":"Fournir une clé publique approuvée et son empreinte avant installation.",
                    "production_modified":False,"build_modified":False}
        if not public_key:
            raise ActivationError(
                "Activation refusée : aucune clé publique Ed25519 approuvée. "
                "Ne pas générer de clé privée sur OVH ni supprimer cette vérification.")
        # provision() refuses mismatched pinned fingerprints, symlinks and
        # existing configurations. Only configuration + public key are copied.
        provision(BASE_URL,Path(public_key),fingerprint,channel)
    elif public_key or fingerprint:
        raise ActivationError("Source déjà configurée : remplacement de clé interdit")
    state=_json_ctl("status")
    if not state.get("configured") or not state.get("can_check"):
        raise ActivationError("Moteur non raccordé à la source signée")
    # Do not require release existence for provisioning: an empty channel is
    # a future publication dependency, NOT an excuse to fabricate one.
    published=_tls_probe(BASE_URL+"/channels/"+state["channel"]+".json")
    result="waiting_for_signed_release"
    if published:
        result="published_not_verified"  # HTTP 200 is not cryptographic verification.
        if install:
            state=_json_ctl("check")
            reason=state.get("reason_code")
            if reason in ("release_ready","already_current"):
                result="ready"
            elif reason=="release_not_compatible":
                result="incompatible_release"
            else:
                result="verification_failed"
    after=_network_snapshot()
    if before!=after:
        raise ActivationError("Configuration réseau inattendue modifiée")
    # Read-only search for signed releases every six hours. The Web UI alone
    # can request an actual installation after a signature check.
    if install:
        _start_periodic_checks()
    return {"status":result,
            "source":BASE_URL,"channel":state["channel"],
            "configured":True,"channel_http_present":published,
            "can_check":bool(state.get("can_check")),
            "installable":bool(state.get("installable")) if result=="ready" else False,
            "network_modified":False,"build_modified":False,
            "periodic_checks_enabled":bool(install),
            "notes":"Le canal est vérifié et les versions compatibles peuvent être installées via le panneau."
             if result=="ready" else
             "Distribution non prête de bout en bout : vérifier le canal, la signature et la compatibilité."}


def main():
    parser=argparse.ArgumentParser(description="Activer une fois la source signée sur RISE-1")
    parser.add_argument("--install",action="store_true")
    parser.add_argument("--public-key",type=Path)
    parser.add_argument("--fingerprint")
    parser.add_argument("--channel",choices=("stable","beta"),default="beta")
    args=parser.parse_args()
    try:
        result=activate(install=args.install,public_key=args.public_key,
                        fingerprint=args.fingerprint,channel=args.channel)
    except (ActivationError,ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))


if __name__=="__main__":
    main()

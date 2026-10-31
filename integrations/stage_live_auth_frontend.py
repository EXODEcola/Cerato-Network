#!/usr/bin/env python3
"""Stage an authenticating UI shell around the verified historical console.

Does not deploy the files or remove HTTP Basic. Needs full live backend
tests and a same-origin integration review before production activation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from check_live_auth_cutover import BASELINE, _load_json
from inspect_live_auth_compat import inspect

ROOT=Path(__file__).resolve().parents[1]
MARKER="/* CERATO_AUTH_OVERLAY_STAGING"
REQUIRED_JS=(
    "function render(){if(!live)return;",
    "function updates(){",
    "function bind(){",
)
STYLE_MARKER="CERATO NETWORK — Graphite Operations"
MAX_BYTES=2_000_000


class NativeAuthUIStageError(ValueError):
    pass


def _source(path):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=MAX_BYTES:
        raise NativeAuthUIStageError("Source Web absente, symbolique ou trop volumineuse")
    return path.read_bytes()


def stage(source_root:Path,destination:Path, *, baseline:Path=BASELINE)->dict:
    if destination.exists() or destination.is_symlink():
        raise NativeAuthUIStageError("Destination non vierge")
    src=source_root.resolve()
    dest=destination.resolve()
    if dest==src or src in dest.parents or dest in src.parents:
        raise NativeAuthUIStageError("La destination doit être indépendante de l'installation")
    base=_load_json(baseline)
    inventory=inspect(src/"backend/server.py",src/"web/app.js")
    if inventory["server_sha256"]!=base.get("server_sha256"):
        raise NativeAuthUIStageError("Empreinte backend incompatible avec RISE-1")
    app=_source(src/"web/app.js").decode("utf8")
    css=_source(src/"web/style.css").decode("utf8")
    if any(app.count(anchor)!=1 for anchor in REQUIRED_JS):
        raise NativeAuthUIStageError("Interfaces historiques inconnues : aucun patch")
    # The native auth layer rewrites browser fetch() requests. A legacy build
    # using XMLHttpRequest or unknown transports MUST NOT bypass this adapter.
    if "fetch(" not in app or not any(p in app for p in ("'/api/", '"/api/')):
        raise NativeAuthUIStageError("Transport API historique non reconnu : migration refusée")
    if STYLE_MARKER not in css or MARKER in app:
        raise NativeAuthUIStageError("Thème manquant ou migration déjà présente")
    script=_source(ROOT/"web/live-auth-overlay.js").decode("utf8")
    styles=_source(ROOT/"web/live-auth-overlay.css").decode("utf8")
    # Never insert a new script tag that could load arbitrary remote code.
    # The authorized code is appended to the audited existing JavaScript.
    new_js=app.rstrip()+"\n\n"+MARKER+" */\n"+script+"\n"
    new_css=css.rstrip()+"\n\n"+styles+"\n"
    if len(new_js.encode())>MAX_BYTES or len(new_css.encode())>MAX_BYTES:
        raise NativeAuthUIStageError("Patch UI trop volumineux")
    # Ensure the staged layer really includes the modern CSRF adapter.
    # Hiding controls in JavaScript is never used as an authorization check.
    if ("window.fetch=legacyFetch;" not in script or
            "headers.set('X-Cerato-CSRF',state.csrf)" not in script or
            "nativeFetch(path" not in script):
        raise NativeAuthUIStageError("Adaptateur CSRF natif incomplet")
    # Validate syntax before writing any copy.
    result=subprocess.run(["node","--check","-"],input=new_js,
                          text=True,capture_output=True,timeout=10,check=False)
    if result.returncode:
        raise NativeAuthUIStageError("Erreur de syntaxe JavaScript")
    dest.mkdir(parents=True,mode=0o700)
    web=dest/"web"
    web.mkdir(mode=0o700)
    for name,body in (("app.js",new_js),("style.css",new_css)):
        path=web/name
        path.write_text(body,encoding="utf8")
        path.chmod(0o600)
    return {
        "format":"cerato-native-auth-ui-stage-v1",
        "source_backend_verified":True,
        "original_pages_preserved":True,
        "staged_files":["web/app.js","web/style.css"],
        "production_modified":False,
        "nginx_modified":False,
        "network_modified":False,
        "ready_for_production":False,
        "next_requirement":"reviewed backend integration and browser end-to-end test",
    }


def main():
    arg=argparse.ArgumentParser(description="Préparer une interface native privée, sans déploiement")
    arg.add_argument("--source",type=Path,required=True)
    arg.add_argument("--destination",type=Path,required=True)
    parsed=arg.parse_args()
    try:
        result=stage(parsed.source,parsed.destination)
    except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired) as exc:
        arg.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))


if __name__=="__main__":
    main()

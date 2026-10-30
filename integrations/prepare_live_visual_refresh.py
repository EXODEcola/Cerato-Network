#!/usr/bin/env python3
"""Prepare a GRAPHITE UI-only overlay for the EXISTING RISE-1 web console.

Never modifies the running panel, network, sessions, or updater. It requires
the two independently audited source hashes of the original 8787 console.
Run on trusted, isolated copies only. The result is NOT a signed release.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil

from patch_live_update_center import UPDATES_JS
from check_live_auth_cutover import BASELINE, _load_json

ROOT=Path(__file__).resolve().parents[1]
THEME=ROOT/"themes"/"cerato-graphite.css"
MARKER="CERATO NETWORK — Graphite Operations"
RENDER_BOUNDARY="function render(){if(!live)return;"
BODY_START="function updates(){"
LIMIT=2_000_000


class VisualPatchError(ValueError):
    pass


def _read(root:Path,rel:str)->bytes:
    path=root/rel
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=LIMIT:
        raise VisualPatchError("Source Web absente, symbolique ou trop volumineuse: "+rel)
    return path.read_bytes()


def patch_js(app:str)->str:
    """Replace only the pre-existing updater's render function, keep other pages."""
    if app.count(BODY_START)!=1 or app.count(RENDER_BOUNDARY)!=1:
        raise VisualPatchError("Page Mises à jour historique non reconnue")
    start=app.index(BODY_START)
    finish=app.index(RENDER_BOUNDARY)
    if start>=finish or finish-start>32_000:
        raise VisualPatchError("Frontières du rendu des mises à jour inattendues")
    # The updater injects exactly one contiguous function immediately before render().
    before=app[start:finish]
    if not re.fullmatch(r"function updates\(\)\{[\s\S]*\}\s*",before):
        raise VisualPatchError("Fonction updates non isolée")
    new=app[:start]+UPDATES_JS.strip()+"\n"+app[finish:]
    if any(new.count(fragment)!=1 for fragment in
           ("function updates(){", "function render(){if(!live)return;")):
        raise VisualPatchError("Patch du rendu invalide")
    return new


def prepare(source:Path,destination:Path,baseline:Path=BASELINE,theme:Path=THEME):
    source=Path(source)
    destination=Path(destination)
    if source.is_symlink() or not source.is_dir() or destination.exists() or destination.is_symlink():
        raise VisualPatchError("Répertoire source ou destination invalide")
    if destination.resolve()==source.resolve() or source.resolve() in destination.resolve().parents:
        raise VisualPatchError("Destination imbriquée dans les sources")
    expected=_load_json(Path(baseline))
    backend=_read(source,"backend/server.py")
    app=_read(source,"web/app.js")
    stylesheet=_read(source,"web/style.css")
    if (hashlib.sha256(backend).hexdigest()!=expected.get("server_sha256") or
            hashlib.sha256(app).hexdigest()!=expected.get("frontend_sha256")):
        raise VisualPatchError("Les fichiers Web ne correspondent pas à l'audit RISE-1 approuvé")
    theme_bytes=Path(theme).read_bytes()
    if not theme_bytes or len(theme_bytes)>100_000 or MARKER.encode() not in theme_bytes:
        raise VisualPatchError("Thème approuvé manquant")
    if MARKER.encode() in stylesheet:
        raise VisualPatchError("Thème déjà présent: ne pas le dupliquer")
    try:
        patched_app=patch_js(app.decode("utf-8")).encode("utf-8")
    except UnicodeError as exc:
        raise VisualPatchError("Encodage frontend invalide") from exc
    if len(patched_app)>LIMIT or len(stylesheet)+len(theme_bytes)+2>LIMIT:
        raise VisualPatchError("Fichiers patchés trop volumineux")
    prepared={
        "backend/server.py":backend,
        "web/app.js":patched_app,
        "web/style.css":stylesheet+b"\n\n"+theme_bytes,
    }
    # All checks above happen before the first write. No permission-sensitive
    # configs, credentials, keys, routes or other source files are copied.
    destination.mkdir(parents=True,mode=0o700)
    for name,blob in prepared.items():
        target=destination/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(blob)
    return {
        "format":"cerato-graphite-web-stage-v1",
        "prepared_files":list(prepared),
        "source_hashes_verified":True,
        "requires_signed_overlay":True,
        "production_modified":False,
        "network_modified":False,
    }


def main():
    parser=argparse.ArgumentParser(description="Préparer une refonte Graphite du Web RISE-1 (sans installation)")
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--destination",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=prepare(args.source,args.destination)
    except (VisualPatchError,OSError,UnicodeError,ValueError) as exc:
        parser.error(str(exc))
    import json
    print(json.dumps(result,ensure_ascii=False))


if __name__=="__main__":
    main()

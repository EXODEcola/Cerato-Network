#!/usr/bin/env python3
"""Read-only validation of a previously staged RISE-1 Cerato controller.

Never imports or executes the staged controller, network helpers or live
controller. Never prints their source or contents. The verification requires
the exact observed live controller SHA and private root-owned staging files.
This is not an authorization to install or activate routed IPv4.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import stat

SOURCE=Path("/usr/local/sbin/ceratoctl")
SOURCE_SHA="41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6"
STAGED={"ceratoctl","cerato_routed_support.py",
        "routed_nft_inject.py","routed_firewall.py"}
ORIGIN={"cerato_routed_support.py":"live_routed_compat.py",
        "routed_nft_inject.py":"routed_nft_inject.py",
        "routed_firewall.py":"routed_firewall.py"}


class VerificationError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _private_file(path,*,max_bytes=200_000):
    if path.is_symlink() or not path.is_file():
        raise VerificationError("Fichier absent ou lien symbolique interdit")
    st=path.stat()
    if st.st_uid!=0 or (st.st_mode & 0o077):
        raise VerificationError("Fichier non privé ou propriétaire non root")
    if not 0<st.st_size<=max_bytes:
        raise VerificationError("Taille de fichier incorrecte")
    return path.read_bytes()


def _call_count(node,name):
    return sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
               and n.func.id==name for n in ast.walk(node))


def inspect_staged(stage_dir, original=SOURCE, support_dir=None,
                   expected_patched_sha=None):
    stage_dir=Path(stage_dir)
    if not stage_dir.is_absolute() or not str(stage_dir).startswith("/tmp/"):
        raise VerificationError("Le staging doit rester dans /tmp")
    if stage_dir.is_symlink() or not stage_dir.is_dir():
        raise VerificationError("Dossier staging inexistant ou symbolique")
    st=stage_dir.stat()
    if st.st_uid!=0 or (st.st_mode & 0o077):
        raise VerificationError("Dossier staging non privé")
    if set(p.name for p in stage_dir.iterdir())!=STAGED:
        raise VerificationError("Fichiers staging manquants ou inattendus")
    if original!=SOURCE:
        raise VerificationError("Contrôleur live différent du chemin approuvé")
    if original.is_symlink() or not original.is_file():
        raise VerificationError("Contrôleur original absent")
    original_raw=original.read_bytes()
    if sha256(original_raw)!=SOURCE_SHA:
        raise VerificationError("Le contrôleur live a changé depuis le staging")
    patched_raw=_private_file(stage_dir/"ceratoctl")
    staged_sha=sha256(patched_raw)
    if expected_patched_sha is not None and staged_sha!=expected_patched_sha:
        raise VerificationError("Empreinte staging différente du résultat approuvé")
    if patched_raw==original_raw:
        raise VerificationError("La copie est identique à l'original")
    try:
        tree=ast.parse(patched_raw.decode("utf-8"))
        compile(tree,"<staged-ceratoctl-not-executed>","exec")
    except (UnicodeError,SyntaxError,TypeError) as exc:
        raise VerificationError("Contrôleur stagé non compilable") from exc
    funcs={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in (
                "render_nft","rewrite_wg_peers"):
            if node.name in funcs:
                raise VerificationError("Fonction réseau dupliquée")
            funcs[node.name]=node
    if set(funcs)!={"render_nft","rewrite_wg_peers"}:
        raise VerificationError("Points d'entrée réseau absents")
    counts={"render_nft":_call_count(funcs["render_nft"],"routed_render_nft"),
            "rewrite_wg_peers":_call_count(funcs["rewrite_wg_peers"],"routed_extend_wg")}
    if counts!={"render_nft":1,"rewrite_wg_peers":1}:
        raise VerificationError("Injection réseau absente, multiple ou inattendue")
    imports=[node for node in tree.body if isinstance(node,ast.ImportFrom) and
             node.module=="cerato_routed_support"]
    if len(imports)!=1 or set(a.name for a in imports[0].names)!={
            "routed_render_nft","routed_extend_wg"}:
        raise VerificationError("Import des modules de compatibilité invalide")
    support_checks={}
    for dest,src in ORIGIN.items():
        raw=_private_file(stage_dir/dest)
        try:
            ast.parse(raw.decode("utf-8"))
            compile(raw,dest,"exec")
        except (UnicodeError,SyntaxError,TypeError) as exc:
            raise VerificationError("Module de compatibilité non compilable") from exc
        if support_dir is not None:
            expected=Path(support_dir)/src
            if expected.is_symlink() or not expected.is_file() or raw!=expected.read_bytes():
                raise VerificationError("Module de compatibilité différent des sources")
        support_checks[dest]=sha256(raw)
    return {
        "status":"review-only-verified",
        "controller_sha256":SOURCE_SHA,
        "patched_sha256":staged_sha,
        "hook_calls":counts,
        "support_sha256":support_checks,
        "source_unmodified":True,
        "network_modified":False,
        "ready_to_install":False,
        "ready_for_routed_ip":False,
        "note":"Contrôles statiques uniquement, sans exécuter ceratoctl ou nft",
    }


def main():
    parser=argparse.ArgumentParser(description="Verify a copy-only Cerato routing stage")
    parser.add_argument("--stage",required=True)
    parser.add_argument("--support-dir")
    parser.add_argument("--patched-sha",required=True)
    args=parser.parse_args()
    if len(args.patched_sha)!=64 or any(c not in "0123456789abcdef" for c in args.patched_sha):
        parser.error("SHA-256 staging invalide")
    try:
        result=inspect_staged(args.stage,support_dir=args.support_dir,
                              expected_patched_sha=args.patched_sha)
    except (VerificationError,OSError,ValueError,KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

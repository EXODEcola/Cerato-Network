#!/usr/bin/env python3
"""Stage a REPRODUCIBLE patched COPY of the precise RISE-1 controller.

Does not install, execute, import or modify ceratoctl, WG, nftables or systemd.
Fails closed on SHA changes, ambiguous AST shapes or an unsafe destination.
The output is a development review artifact, not a deployable release.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import os
import stat

SOURCE=Path("/usr/local/sbin/ceratoctl")
EXPECTED_CONTROLLER_SHA="41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6"
STAGING_FILES=("live_routed_compat.py","routed_nft_inject.py","routed_firewall.py")


class StageError(ValueError):
    pass


def source_is_controller(source,sha):
    if not source.is_file() or source.is_symlink():
        raise StageError("Contrôleur Cerato absent ou lien symbolique")
    data=source.read_bytes()
    if hashlib.sha256(data).hexdigest()!=sha:
        raise StageError("SHA256 de ceratoctl différent : correctif refusé")
    if len(data)>100_000:
        raise StageError("Source trop volumineuse")
    return data


def _simple_name(node,expected):
    return isinstance(node,ast.Name) and node.id==expected


def transform(raw):
    try:
        tree=ast.parse(raw.decode("utf-8"))
    except (SyntaxError,UnicodeError) as exc:
        raise StageError("Contrôleur non Python") from exc
    targets={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in (
                "render_nft","rewrite_wg_peers"):
            if node.name in targets:
                raise StageError("Fonction dupliquée")
            targets[node.name]=node
    if set(targets)!={"render_nft","rewrite_wg_peers"}:
        raise StageError("Fonctions réseau manquantes")
    render=targets["render_nft"]
    wg=targets["rewrite_wg_peers"]
    for node in (render,wg):
        if (len(node.args.args)!=1 or node.args.args[0].arg!="data" or
                node.args.kwonlyargs or node.args.vararg or node.args.kwarg):
            raise StageError("Signature du générateur modifiée")
    returns=[(i,node) for i,node in enumerate(render.body)
             if isinstance(node,ast.Return)]
    if len(returns)!=1 or returns[0][0]!=len(render.body)-1:
        raise StageError("Retour render_nft inattendu")
    last=returns[0][1]
    if last.value is None:
        raise StageError("render_nft retourne None")
    last.value=ast.Call(func=ast.Name(id="routed_render_nft",ctx=ast.Load()),
                        args=[last.value,ast.Name(id="data",ctx=ast.Load())],
                        keywords=[])
    # The observed function writes 'original' to a staged WG config then
    # replaces it. Do not modify the original peer-rendering expressions.
    positions=[]
    for index,node in enumerate(wg.body):
        if (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and
            isinstance(node.value.func,ast.Attribute) and
            node.value.func.attr=="write_text" and
            len(node.value.args)==1 and
            _simple_name(node.value.args[0],"original")):
            positions.append(index)
    if len(positions)!=1:
        raise StageError("Écriture WireGuard non reconnue")
    idx=positions[0]
    write=wg.body[idx].value
    if not isinstance(write.func.value,ast.Name) or write.func.value.id!="temp":
        raise StageError("Cible de WG non reconnue")
    assign=ast.Assign(
        targets=[ast.Name(id="original",ctx=ast.Store())],
        value=ast.Call(func=ast.Name(id="routed_extend_wg",ctx=ast.Load()),
                       args=[ast.Name(id="original",ctx=ast.Load()),
                             ast.Name(id="data",ctx=ast.Load())],keywords=[]))
    wg.body.insert(idx,assign)
    imports=ast.ImportFrom(module="cerato_routed_support",
        names=[ast.alias(name="routed_render_nft"),ast.alias(name="routed_extend_wg")],level=0)
    point=0
    if (tree.body and isinstance(tree.body[0],ast.Expr) and
        isinstance(tree.body[0].value,(ast.Constant,)) and
        isinstance(tree.body[0].value.value,str)):
        point=1
    while (point<len(tree.body) and isinstance(tree.body[point],ast.ImportFrom)
           and tree.body[point].module=="__future__"):
        point+=1
    tree.body.insert(point,imports)
    try:
        rewritten="#!/usr/bin/env python3\n"+ast.unparse(ast.fix_missing_locations(tree))+"\n"
        ast.parse(rewritten)
    except (SyntaxError,ValueError,TypeError) as exc:
        raise StageError("Transformation AST invalide") from exc
    ensure_header = rewritten.startswith("#!/usr/bin/env python3\\n")
    if not ensure_header:
        raise StageError("En-tête Python exécutable absent")
    return rewritten.encode("utf-8")


def stage(source,destination,helper_dir,sha):
    if source!=SOURCE or sha!=EXPECTED_CONTROLLER_SHA:
        raise StageError("Source ou empreinte RISE-1 non approuvée")
    raw=source_is_controller(source,sha)
    if destination.exists() or destination.is_symlink():
        raise StageError("Destination déjà présente : écrasement interdit")
    if not destination.is_absolute() or not str(destination).startswith("/tmp/"):
        raise StageError("Staging uniquement dans /tmp")
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise StageError("Destination staging invalide")
    if not helper_dir.is_dir() or helper_dir.is_symlink():
        raise StageError("Bibliothèque de staging absente")
    for filename in STAGING_FILES:
        path=helper_dir/filename
        if not path.is_file() or path.is_symlink() or path.stat().st_size>100_000:
            raise StageError("Bibliothèque de staging invalide")
    patched=transform(raw)
    mode=destination.parent.stat().st_mode
    if mode & stat.S_IWOTH:
        raise StageError("Dossier staging accessible en écriture à tous")
    destination.mkdir(mode=0o700)
    output=destination/"ceratoctl"
    output.write_bytes(patched)
    os.chmod(output,0o600)
    filenames={
        "live_routed_compat.py":"cerato_routed_support.py",
        "routed_nft_inject.py":"routed_nft_inject.py",
        "routed_firewall.py":"routed_firewall.py",
    }
    for src,dst in filenames.items():
        item=destination/dst
        item.write_bytes((helper_dir/src).read_bytes())
        os.chmod(item,0o600)
    compile(patched, str(output), "exec")
    return {
        "status":"staged-only","ready_to_install":False,"network_modified":False,
        "source_sha256":sha,"patched_sha256":hashlib.sha256(patched).hexdigest(),
        "support_modules":sorted(filenames.values()),"destination":str(destination),
        "warning":"Ne pas installer le contrôleur patché ni réappliquer nftables ou WG",
    }


def main():
    p=argparse.ArgumentParser(description="Prepare a review-only Cerato controller copy")
    p.add_argument("--controller-sha",required=True)
    p.add_argument("--source",default=str(SOURCE))
    p.add_argument("--destination",required=True)
    p.add_argument("--support-dir",required=True)
    args=p.parse_args()
    try:
        result=stage(Path(args.source),Path(args.destination),
                     Path(args.support_dir),args.controller_sha)
    except (StageError,ValueError,TypeError,OSError) as exc:
        p.error(str(exc))
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()

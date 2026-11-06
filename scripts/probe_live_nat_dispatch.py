#!/usr/bin/env python3
"""Read-only *redacted* NAT dispatcher shape audit for the live RISE-1 Web.

Does not execute/import backend code, query APIs, access any credential files,
print source lines, body literals, network config or keys. Detects the
structure of the actual legacy POST NAT handler to adapt a fail-closed
signed Web patch. AST only, never a deployment approval.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path

BACKEND=Path("/opt/cerato-network/backend/server.py")
NAT_ROUTES=frozenset({"/api/nat/add","/api/nat","/api/nat/remove"})
LIMIT=400_000

class ProbeError(ValueError):
    pass

def _method_name(node):
    if isinstance(node,ast.Call):
        func=node.func
        if isinstance(func,ast.Attribute):
            return func.attr
        if isinstance(func,ast.Name):
            return func.id
    return None

def _is_p_branch(test):
    """Exact p-comparison, no fuzzy substring search through source."""
    if not isinstance(test,ast.Compare) or not isinstance(test.left,ast.Name) or test.left.id!="p":
        return False
    if (len(test.ops)!=1 or not isinstance(test.ops[0],ast.Eq)
            or len(test.comparators)!=1
            or not isinstance(test.comparators[0],ast.Constant)
            or not isinstance(test.comparators[0].value,str)):
        return False
    return test.comparators[0].value in NAT_ROUTES

def _route_values(test):
    result=set()
    for node in ast.walk(test):
        if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value in NAT_ROUTES:
            result.add(node.value)
    return sorted(result)

def _read_body_assigns(method):
    assigns=[]
    for node in ast.walk(method):
        if isinstance(node,(ast.Assign,ast.AnnAssign)):
            value=node.value
            if _method_name(value)=="read_body":
                target=node.targets[0] if isinstance(node,ast.Assign) and len(node.targets)==1 else (
                    node.target if isinstance(node,ast.AnnAssign) else None)
                if isinstance(target,ast.Name):
                    # Report only exact, predetermined variable tokens.
                    variable=target.id if target.id in ("b","body","data","payload","request") else "other"
                    assigns.append({"line":node.lineno,"variable":variable})
    return sorted(assigns,key=lambda x:x["line"])

def _guard_calls(method):
    return sorted(node.lineno for node in ast.walk(method)
                  if isinstance(node,ast.Call) and _method_name(node)=="check_session"
                  and any(kw.arg=="write" and isinstance(kw.value,ast.Constant) and kw.value.value is True
                          for kw in node.keywords))

def analyze(source):
    if not isinstance(source,str) or not source or len(source.encode("utf8"))>LIMIT:
        raise ProbeError("Backend absent ou hors limites")
    tree=ast.parse(source,filename="server.py")
    handlers=[]
    for cls in (node for node in ast.walk(tree) if isinstance(node,ast.ClassDef)):
        for method in cls.body:
            if not isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) or method.name!="do_POST":
                continue
            branches=[]
            guard_lines=_guard_calls(method)
            read_assigns=_read_body_assigns(method)
            # All if/elif alternatives in this exact method, not random module literals.
            for node in ast.walk(method):
                if not isinstance(node,ast.If):
                    continue
                routes=_route_values(node.test)
                if not routes:
                    continue
                safe=_is_p_branch(node.test)
                branch={
                  "routes":routes,
                  "line":node.lineno,
                  "syntax":"direct-p-compare" if safe else "noncanonical-expression",
                  "column":node.col_offset,
                  "before_branch_write_auth_present":any(l<node.lineno for l in guard_lines),
                  "before_branch_body_read":next(
                     (x["variable"] for x in reversed(read_assigns) if x["line"]<node.lineno), None),
                }
                branches.append(branch)
            handlers.append({
                "post_start_line":method.lineno,
                "post_end_line":method.end_lineno,
                "nat_branches":sorted(branches,key=lambda v:v["line"]),
                "write_auth_call_count":len(guard_lines),
                "body_read_assignments":len(read_assigns),
            })
    if len(handlers)>8:
        raise ProbeError("Nombre de handlers HTTP inattendu")
    return {
        "schema":"cerato-nat-dispatch-shape-v1",
        "backend_sha256":hashlib.sha256(source.encode("utf8")).hexdigest(),
        "handlers":handlers,
        "nat_add_direct_branch_found":any(
            "/api/nat/add" in b["routes"] and b["syntax"]=="direct-p-compare"
            for h in handlers for b in h["nat_branches"]),
        "source_code_exported":False,
        "secrets_exported":False,
        "production_modified":False,
        "network_modified":False,
        "safe_to_patch_automatically":False,
        "note":"Structure AST uniquement. Une authentification simplement présente avant la branche n'établit pas sa dominance réelle.",
    }

def audit(path=BACKEND):
    if path.is_symlink() or not path.is_file():
        raise ProbeError("Backend absent ou symbolique")
    if not 0<path.stat().st_size<=LIMIT:
        raise ProbeError("Backend hors limites")
    return analyze(path.read_text(encoding="utf8"))

def main():
    p=argparse.ArgumentParser(description="Audit lecture seule du dispatch NAT RISE-1")
    p.add_argument("--backend",type=Path,default=BACKEND)
    args=p.parse_args()
    try:
        result=audit(args.backend)
    except (ProbeError,OSError,UnicodeError,SyntaxError) as exc:
        p.error(str(exc))
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))

if __name__=="__main__":
    main()

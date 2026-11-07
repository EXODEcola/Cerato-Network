#!/usr/bin/env python3
"""Explain startup hazards in the SHA-pinned private Cerato Network backend.

READ ONLY: no import or execution of private server.py, no HTTP listener,
no subprocess from private code, no network mutation, no credentials output.
The source remains on RISE-1. This is a classification, NOT proof of safety.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from collections import Counter

from audit_private_live_http_boundary import (
    LIVE, EXPECTED, ExecutionBoundaryError, inspect as boundary_inspect,
    safe_read, digest,
)

KNOWN_IO_NAMES=frozenset({"Popen","system","check_output"})
KNOWN_IO_METHODS=frozenset({
    "run","Popen","system","bind","connect","serve_forever",
    "check_output","start_server",
})

def is_main_guard(test:ast.AST)->bool:
    """Only the literal __name__ == '__main__' is considered guarded."""
    if not isinstance(test,ast.Compare) or len(test.ops)!=1 or not isinstance(test.ops[0],ast.Eq) or len(test.comparators)!=1:
        return False
    a,b=test.left,test.comparators[0]
    return ((isinstance(a,ast.Name) and a.id=="__name__"
             and isinstance(b,ast.Constant) and b.value=="__main__")
            or (isinstance(b,ast.Name) and b.id=="__name__"
                and isinstance(a,ast.Constant) and a.value=="__main__"))

def risk_call(node:ast.Call)->bool:
    f=node.func
    return ((isinstance(f,ast.Name) and f.id in KNOWN_IO_NAMES)
            or (isinstance(f,ast.Attribute) and f.attr in KNOWN_IO_METHODS))

def startup_profile(source:bytes)->dict:
    try:
        tree=ast.parse(source.decode("utf8"),filename="private-live-server.py")
    except (SyntaxError,UnicodeError) as exc:
        raise ExecutionBoundaryError("Structure de démarrage inconnue") from exc

    if sum(1 for _ in ast.walk(tree))>100_000:
        raise ExecutionBoundaryError("Source trop complexe pour le contrôle")

    counts=Counter()
    io=Counter()
    # Walks all expressions but never invokes them; imports are NOT resolved.
    class Visitor(ast.NodeVisitor):
        context="import"

        def with_context(self,context,items):
            prev=self.context
            self.context=context
            try:
                for item in items:
                    self.visit(item)
            finally:
                self.context=prev

        def visit_Call(self,node):
            if risk_call(node):
                io[self.context]+=1
            self.generic_visit(node)

        def visit_FunctionDef(self,node):
            # Defaults and decorators execute when the function is defined.
            self.with_context(self.context,node.decorator_list)
            self.with_context(self.context,node.args.defaults)
            self.with_context(self.context,[n for n in node.args.kw_defaults if n is not None])
            if node.returns is not None:
                self.with_context(self.context,[node.returns])
            counts["function_definitions"]+=1
            self.with_context("deferred",node.body)

        visit_AsyncFunctionDef=visit_FunctionDef

        def visit_ClassDef(self,node):
            counts["class_definitions"]+=1
            self.with_context(self.context,node.decorator_list+node.bases)
            self.with_context(self.context,[keyword.value for keyword in node.keywords])
            # Class body runs at definition time, whereas its methods wait.
            self.with_context(self.context,node.body)

        def visit_If(self,node):
            if self.context=="import" and is_main_guard(node.test):
                counts["main_guard_blocks"]+=1
                self.with_context("main_guard",node.body)
                self.with_context("import",node.orelse)
            else:
                self.visit(node.test)
                self.with_context(self.context,node.body+node.orelse)

    vis=Visitor()
    vis.visit(tree)
    for node in tree.body:
        if isinstance(node,(ast.Import,ast.ImportFrom)):
            counts["imports_executed_on_load"]+=1
        elif isinstance(node,ast.ClassDef):
            counts["class_bodies_evaluated_on_load"]+=1
            if node.decorator_list:
                counts["classes_with_decorators"]+=1
        elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            if node.decorator_list:
                counts["functions_with_decorators"]+=1
            if node.args.defaults or node.args.kw_defaults:
                counts["functions_with_defaults"]+=1
        elif isinstance(node,ast.If) and is_main_guard(node.test):
            counts["main_guard_top_level"]+=1
        elif isinstance(node,ast.Assign):
            if any(isinstance(x,(ast.Call,ast.Await,ast.Yield,
                                 ast.YieldFrom,ast.ListComp,ast.SetComp,
                                 ast.DictComp,ast.GeneratorExp))
                   for x in ast.walk(node.value)):
                counts["top_level_assignment_dynamic"]+=1
            else:
                counts["top_level_assignment_literal_or_reference"]+=1
        elif isinstance(node,ast.AnnAssign):
            if node.value is not None and any(
                isinstance(x,(ast.Call,ast.Await,ast.ListComp,ast.SetComp,
                              ast.DictComp,ast.GeneratorExp))
                for x in ast.walk(node.value)):
                counts["top_level_assignment_dynamic"]+=1
            else:
                counts["top_level_assignment_literal_or_reference"]+=1
        elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str):
            counts["module_docstrings"]+=1
        elif isinstance(node,ast.Pass):
            continue
        else:
            counts["top_level_other_runtime_statements"]+=1

    total=sum(io.values())
    # The original coarse audit counted all these call sites together.
    return {
        "format":"cerato-private-live-startup-map-v1",
        "top_level_imports":counts["imports_executed_on_load"],
        "top_level_main_guards":counts["main_guard_top_level"],
        "top_level_dynamic_assignments":counts["top_level_assignment_dynamic"],
        "top_level_reference_assignments":counts["top_level_assignment_literal_or_reference"],
        "top_level_other_runtime_statements":counts["top_level_other_runtime_statements"],
        "class_bodies_evaluated_on_load":counts["class_bodies_evaluated_on_load"],
        "classes_with_decorators":counts["classes_with_decorators"],
        "functions_with_decorators":counts["functions_with_decorators"],
        "functions_with_defaults":counts["functions_with_defaults"],
        "suspected_external_call_sites":total,
        "suspected_external_call_sites_at_import":io["import"],
        "suspected_external_call_sites_guarded_main":io["main_guard"],
        "suspected_external_call_sites_deferred":io["deferred"],
        "import_may_trigger_module_side_effects":counts["imports_executed_on_load"]>0,
        "static_analysis_can_prove_safe_execution":False,
        "safe_to_execute_private_backend":False,
        "safe_to_cut_over":False,
        "network_modified":False,
        "production_modified":False,
        "private_source_exported":False,
    }

def inspect():
    if os.geteuid()!=0:
        raise ExecutionBoundaryError("Contrôle réservé à root sur RISE-1")
    # This rechecks candidate fingerprint and crypto preflights.
    previous=boundary_inspect()
    original=safe_read(LIVE/"backend/server.py")
    if digest(original)!=EXPECTED["server_sha256"]:
        raise ExecutionBoundaryError("Version privée active différente de l'audit")
    output=startup_profile(original)
    if output["suspected_external_call_sites"]!=previous["possible_external_or_socket_call_count"]:
        raise ExecutionBoundaryError("Analyse du nombre des appels incohérente")
    return {
        **output,
        "sha256_verified":True,
        "inactive_candidate_verified":previous["inactive_candidate_integrity_verified"],
        "runtime_verified":previous["cryptographic_runtime_validated_under_web_user"],
        "legacy_guarded":False,
        "full_http_backend_isolation_verified":False,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check",action="store_true",required=True)
    parser.parse_args()
    try:
        print(json.dumps(inspect(),ensure_ascii=False,sort_keys=True,indent=2))
    except (ExecutionBoundaryError,OSError,ValueError) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()

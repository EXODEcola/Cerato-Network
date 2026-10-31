"""Explicit legacy Cerato Network RBAC inventory for future 8787 migration.

This is a pure policy module, NOT yet installed into the live RISE-1 server.
The deployed backend must check it before running old ceratoctl/ipctl and
return viewer_projection for read-only users. Unknown APIs deny by default.
No access is granted solely by hiding menu items in JavaScript.
"""
from __future__ import annotations
from auth_store import Forbidden

PUBLIC={
    ("GET","/api/auth/setup-status"),
    ("POST","/api/auth/setup"),
    ("POST","/api/auth/login"),
    ("POST","/api/auth/mfa/verify"),
}
VIEWER={
    ("GET","/api/status"),
    ("GET","/api/auth/me"),
    ("POST","/api/auth/logout"),
    ("PATCH","/api/auth/me"),
}
ADMIN_READ={
    ("GET","/api/session"),
    ("GET","/api/events"),
    ("GET","/api/nft-preview"),
    ("GET","/api/wg-config"),
    ("GET","/api/updates"),
    ("GET","/api/peers"),
    ("GET","/api/nat"),
    ("GET","/api/ip"),
    ("GET","/api/firewall"),
    ("GET","/api/topology"),
    ("GET","/api/logs"),
}
ADMIN_WRITE={
    ("POST","/api/peers"),
    ("POST","/api/peers/remove"),
    ("POST","/api/ip/add"),
    ("POST","/api/ip/remove"),
    ("POST","/api/ip/preview"),
    ("POST","/api/ip/configure"),
    ("POST","/api/nat/add"),
    ("POST","/api/nat/remove"),
    ("POST","/api/enroll/token"),
    ("POST","/api/updates/check"),
    ("POST","/api/updates/install"),
    ("POST","/api/updates/rollback"),
    ("POST","/api/updates/stage"),
}
ACCOUNT={
    ("GET","/api/accounts"),
    ("POST","/api/accounts"),
}
for _group in (VIEWER,ADMIN_READ,ADMIN_WRITE,ACCOUNT):
    if PUBLIC & _group:
        raise RuntimeError("Public route must never overlap protected routes")
if ADMIN_READ & ADMIN_WRITE or VIEWER & ADMIN_READ or VIEWER & ADMIN_WRITE:
    raise RuntimeError("Duplicate privilege levels detected")


def privilege(method:str,path:str)->str:
    """Return privilege needed; raise on routes not explicitly reviewed."""
    pair=(str(method).upper(),str(path).split("?",1)[0])
    if pair in PUBLIC:
        return "public"
    if pair in VIEWER:
        return "view"
    if pair in ADMIN_READ:
        return "view_sensitive"
    if pair in ADMIN_WRITE:
        return "network_write"
    if pair in ACCOUNT:
        return "accounts_manage"
    parts=pair[1].strip("/").split("/")
    if len(parts)==3 and parts[:2]==["api","accounts"] and parts[2].isdigit():
        if pair[0] in ("GET","PATCH","DELETE"):
            return "accounts_manage"
    raise Forbidden("Route du panneau historique non autorisée par la nouvelle politique.")


def allow(method:str,path:str,actor:dict|None)->str:
    """Pure role check; session, MFA and CSRF must be checked by middleware."""
    permission=privilege(method,path)
    if permission=="public":
        return permission
    if not isinstance(actor,dict) or not actor.get("active",True):
        raise Forbidden("Session requise")
    role=actor.get("role")
    if role not in ("owner","admin","user"):
        raise Forbidden("Rôle inconnu")
    if role=="user" and permission!="view":
        raise Forbidden("Compte en lecture seule")
    return permission


def audit_gaps(observed_routes:list[str])->list[str]:
    """List legacy API routes requiring an explicit RBAC decision.

    The operator uses the safe inventory from inspect_live_auth_compat.py.
    New or unexpected routes remain blocked until reviewed, not auto-allowed.
    """
    if not isinstance(observed_routes,list):
        raise ValueError("Expected route list")
    gaps=[]
    for route in observed_routes:
        if not isinstance(route,str) or not route.startswith("/api/"):
            continue
        # A route can have only a GET or only a mutation handler.
        if not any((method,route) in (PUBLIC|VIEWER|ADMIN_READ|ADMIN_WRITE|ACCOUNT)
                   for method in ("GET","POST","PATCH","DELETE")):
            gaps.append(route)
    return sorted(set(gaps))

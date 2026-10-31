#!/usr/bin/env python3
"""Offline compatibility render of RISE-1's exact known controller and stage.

Extract ONLY the trusted render_nft(data) function via AST, with a restricted
global namespace. Compare the real current Cerato config's old and patched
nftables render, then simulate moving a single Additional /32 from legacy
NAT to routed-WG on a deep-copied config. NO shell commands, no nft, WG, IP,
systemctl, sysctl, filesystem writes, or imports of either controller.
Never print full config, peer keys, private keys or nftables output.

This is a simulation, not a migration, security certification or permit to
use the staged controller on production.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys

CONTROLLER=Path("/usr/local/sbin/ceratoctl")
CONFIG=Path("/etc/cerato-network/config.json")
STATE=Path("/etc/cerato-network/additional-ip-managed.json")
APPROVED_SOURCE_SHA="41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6"
APPROVED_PATCHED_SHA="4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793"
APPROVED_SUPPORT={
    "cerato_routed_support.py":"760453925d7b3cb2af4165723412bfc4aaaf26be1b036c84f2ad9dbc67b67950",
    "routed_firewall.py":"4f8818bb6ef6873760192c3b7db65d232602ff94a5a51300ae1f5ac40476fc74",
    "routed_nft_inject.py":"98cfbcc1aaa994ef11aa34ed8ba6fe85aafc2f94ae756aadb968d8acbbf01204",
}


class SimulationError(ValueError):
    pass


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _read_exact(path,expected,maximum=160_000):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>maximum:
        raise SimulationError("Fichier inconnu ou symbolique")
    content=path.read_bytes()
    if _sha(content)!=expected:
        raise SimulationError("Empreinte de fichier non approuvée")
    return content


def _json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1_000_000:
        raise SimulationError("État Cerato absent ou symbolique")
    try:
        result=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,ValueError,UnicodeError) as exc:
        raise SimulationError("État Cerato non lisible") from exc
    if not isinstance(result,dict):
        raise SimulationError("État Cerato non objet")
    return result


def _render_function(raw,*,modified=False):
    """Compile only a recognized pure AST function, NOT the controller module."""
    try:
        tree=ast.parse(raw.decode("utf-8"))
    except (UnicodeError,SyntaxError,ValueError) as exc:
        raise SimulationError("Source Python incorrecte") from exc
    found=[node for node in tree.body
           if isinstance(node,ast.FunctionDef) and node.name=="render_nft"]
    if len(found)!=1 or len(found[0].args.args)!=1 or found[0].args.args[0].arg!="data":
        raise SimulationError("Fonction render_nft inattendue")
    node=found[0]
    blocked=(ast.Import,ast.ImportFrom,ast.With,ast.AsyncWith,ast.Global,
             ast.Nonlocal,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef,
             ast.While,ast.Await,ast.Yield,ast.YieldFrom,ast.Try)
    allowed_calls={
        "re.fullmatch","ipaddress.ip_address","sorted",
        "str","len","ValueError","entries.append","entries.extend",
        "m.get","literal.join","routed_render_nft",
    }
    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child,blocked):
            raise SimulationError("Fonction contenant des structures non approuvées")
        if isinstance(child,ast.Call):
            if isinstance(child.func,ast.Name):
                name=child.func.id
            elif isinstance(child.func,ast.Attribute) and isinstance(child.func.value,ast.Name):
                name=child.func.value.id+"."+child.func.attr
            elif (isinstance(child.func,ast.Attribute) and child.func.attr=="join"
                  and isinstance(child.func.value,ast.Constant)
                  and isinstance(child.func.value.value,str)):
                name="literal.join"
            else:
                raise SimulationError("Appel non approuvé")
            if name not in allowed_calls:
                raise SimulationError("Appel inconnu dans le moteur nft")
    calls=sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
              and n.func.id=="routed_render_nft" for n in ast.walk(node))
    if calls!=(1 if modified else 0):
        raise SimulationError("Nombre de raccordements différent")
    safe_globals={"__builtins__":{"sorted":sorted,"str":str,"len":len,
                                  "ValueError":ValueError},
                  "re":re,"ipaddress":ipaddress}
    fn=ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[]))
    # Importing the verified pure compatibility helper happens separately;
    # the controller itself is never imported or executed as a module.
    exec(compile(fn,"<isolated-render_nft>","exec"),safe_globals)
    return safe_globals["render_nft"]


def _pure_adapter(stage):
    """Load ONLY hash-pinned pure support modules after static AST checks."""
    for filename,digest in APPROVED_SUPPORT.items():
        content=_read_exact(stage/filename,digest)
        node=ast.parse(content.decode("utf-8"))
        for item in ast.walk(node):
            if isinstance(item,ast.Import):
                imported=[part.name.split(".",1)[0] for part in item.names]
            elif isinstance(item,ast.ImportFrom):
                imported=[(item.module or "").split(".",1)[0]]
            else:
                continue
            if any(name not in ("__future__","ipaddress","re",
                                "routed_nft_inject","routed_firewall")
                   for name in imported):
                raise SimulationError("Import externe interdit dans un helper")
    import types
    names=("routed_firewall","routed_nft_inject","cerato_routed_support")
    before={key:sys.modules.get(key) for key in names}
    old_bytecode=sys.dont_write_bytecode
    sys.dont_write_bytecode=True
    try:
        for name in names:
            spec=importlib.util.spec_from_file_location(name,stage/(name+".py"))
            if spec is None or spec.loader is None:
                raise SimulationError("Module de support indisponible")
            mod=importlib.util.module_from_spec(spec)
            sys.modules[name]=mod
            spec.loader.exec_module(mod)
        helper=sys.modules["cerato_routed_support"]
        return helper.routed_render_nft
    finally:
        sys.dont_write_bytecode=old_bytecode
        for name,prev in before.items():
            if prev is None:
                sys.modules.pop(name,None)
            else:
                sys.modules[name]=prev


def _get_ips(cfg, ip, peer_ip):
    peers=cfg.get("peers")
    if not isinstance(peers,dict):
        raise SimulationError("Pairs Cerato absents")
    matches=[key for key,value in peers.items()
             if isinstance(value,dict) and value.get("ip")==peer_ip]
    if len(matches)!=1:
        raise SimulationError("Pair VPN ambigu ou absent")
    if ip not in cfg.get("pool",[]):
        raise SimulationError("IPv4 absente du pool")
    return matches[0]


def simulate(stage, ip, vpn_ip,management,*,controller=CONTROLLER,
             config=CONFIG,state=STATE):
    # Exact production fingerprints, with private stage files.
    stage=Path(stage)
    if (not stage.is_dir() or stage.is_symlink() or
            stage.stat().st_mode & 0o077):
        raise SimulationError("Dossier staging non privé")
    original=_read_exact(controller,APPROVED_SOURCE_SHA)
    patched=_read_exact(stage/"ceratoctl",APPROVED_PATCHED_SHA)
    cfg=_json(config)
    persisted=_json(state)
    if cfg.get("routed_ipv4",[]) or persisted.get("routed_ipv4",[]):
        raise SimulationError("Une migration routée existe déjà")
    if cfg.get("management_ipv4") not in (None, management):
        raise SimulationError("IP de gestion différente")
    if ipaddress.ip_address(management).is_global is not True:
        raise SimulationError("IP de gestion publique requise")
    if ip==management:
        raise SimulationError("IP principale interdite")
    identity=_get_ips(cfg,ip,vpn_ip)
    if not isinstance(cfg.get("mappings"),list):
        raise SimulationError("Publications NAT invalides")
    old_mapping=[m for m in cfg["mappings"]
                 if isinstance(m,dict) and m.get("public_ip")==ip]
    if len(old_mapping)!=1:
        raise SimulationError("État NAT attendu différent d'une publication")
    local=persisted.get("local_ipv4")
    if not isinstance(local,list) or len([m for m in local
                   if isinstance(m,dict) and m.get("ip")==ip])!=1:
        raise SimulationError("État local persistant inattendu")
    if not isinstance(cfg.get("wan_if"),str) or not isinstance(cfg.get("wg_if"),str):
        raise SimulationError("Interfaces Cerato invalides")

    original_render=_render_function(original)
    patched_render=_render_function(patched,modified=True)
    patched_render.__globals__["routed_render_nft"]=_pure_adapter(stage)

    baseline=original_render(deepcopy(cfg))
    re_render=patched_render(deepcopy(cfg))
    same=baseline==re_render
    if not same:
        raise SimulationError("Rendu NAT historique non préservé")

    # Pure what-if: no config writes or alias/route modifications.
    future=deepcopy(cfg)
    future["mappings"]=[m for m in future["mappings"]
                        if not (isinstance(m,dict) and m.get("public_ip")==ip)]
    future["routed_ipv4"]=[{"ip":ip,"peer":identity}]
    future["management_ipv4"]=management
    routed=patched_render(future)
    in_rule=f'iifname "{cfg["wan_if"]}" oifname "{cfg["wg_if"]}" ip daddr {ip} accept'
    out_rule=f'iifname "{cfg["wg_if"]}" oifname "{cfg["wan_if"]}" ip saddr {ip} accept'
    guard=f'iifname "{cfg["wan_if"]}" ip daddr {ip} drop'
    if in_rule not in routed or out_rule not in routed or guard not in routed:
        raise SimulationError("Règles /32 routées ou INPUT absentes")
    if re.search(re.escape(ip)+r"\s+tcp dport \d+ dnat to",routed):
        raise SimulationError("DNAT ancienne toujours présente")
    return {
        "format":"cerato-routed-render-dry-run-v1",
        "status":"validated-in-memory",
        "current_legacy_render_unchanged":same,
        "original_controller_sha256":APPROVED_SOURCE_SHA,
        "staged_controller_sha256":APPROVED_PATCHED_SHA,
        "expected_public_ip":ip,
        "vpn_peer_ip":vpn_ip,
        "legacy_nat_mappings_detected":len(old_mapping),
        "virtual_nat_mappings_removed":len(old_mapping),
        "virtual_forward_inbound":True,
        "virtual_forward_outbound":True,
        "virtual_gateway_input_drop_preserved":True,
        "virtual_other_nat_mappings_preserved":len(future["mappings"]),
        "configuration_files_modified":False,
        "network_modified":False,
        "ready_to_install":False,
        "ready_for_routed_ip":False,
        "limitations":["Agent Dell absent","Retour arrière coordonné non testé",
                       "Persistance réelle et WireGuard non activés",
                       "Aucune vérification d'accès depuis Internet"],
    }


def main():
    p=argparse.ArgumentParser(description="RISE-1 read-only nft renderer dry-run")
    p.add_argument("--stage",required=True)
    p.add_argument("--public-ip",required=True)
    p.add_argument("--vpn-ip",required=True)
    p.add_argument("--management-ip",required=True)
    a=p.parse_args()
    try:
        result=simulate(Path(a.stage),a.public_ip,a.vpn_ip,a.management_ip)
    except (SimulationError,ValueError,TypeError,AttributeError,KeyError) as exc:
        p.error(str(exc))
    print(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False))


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Cerato Network /32 rollout: fail-closed two-host staged deployment.

This program is NOT an OVH API client. Root-only explicit stages:
  prepare --role peer/gateway -> stage locally, backup and arm persistent timer
  activate --role ...        -> perform reversible live change
  commit --role ...          -> persist only after independent external verification
  rollback --role ...        -> restore original state
No silent commits. A failed operation starts rollback and leaves a
persistent watchdog armed until restoration is complete.

Intended baseline:
 OVH RISE-1 51.210.223.57 on enp1s0f0, WG 10.77.0.1
 Dell R530 WG 10.77.0.2, Tailscale recovery.
 Public /32 54.37.165.151.
 This doesn't change Dell's main LAN default route or Tailscale.

WARNING: never activate before OVH virtual MAC has been deleted and the
public IPv4 has been verified externally; this tool cannot prove API state.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
import datetime as datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PUB="54.37.165.151"
ADMIN="51.210.223.57"
VPN="10.77.0.2"
WAN="enp1s0f0"
WG="wg-cerato"
TABLE="51820"
RULE_PRIORITY=1101
SOURCE_SHA="41e11e267af622b608a40403d1d8d976903e9ea88470a078a7e568854935f2b6"
PATCHED_SHA="4eb69872bf571b678f469eb33dc6cff26f0adf468aa1d98b1b39b943a02fa793"
HELPER_SHA={
    "live_routed_compat.py":"760453925d7b3cb2af4165723412bfc4aaaf26be1b036c84f2ad9dbc67b67950",
    "routed_nft_inject.py":"3f60268c1532d86ddbdd873be5471948636b7455390163044d0851ffe82eb299",
    "routed_firewall.py":"4f8818bb6ef6873760192c3b7db65d232602ff94a5a51300ae1f5ac40476fc74",
}
CONTROLLER=Path("/usr/local/sbin/ceratoctl")
CFG=Path("/etc/cerato-network/config.json")
STATE=Path("/etc/cerato-network/additional-ip-managed.json")
BASE=Path("/var/lib/cerato-network/routed-54-37-165-151")
BIN=Path("/usr/local/sbin/cerato-routed-cutover")
FW_TABLE="cerato_peer_public"
UNIT="cerato-routed"
DEADLINE_GATEWAY=25
DEADLINE_PEER=45
EXPECTED_SUPPORT=("cerato_routed_support.py","routed_nft_inject.py","routed_firewall.py")

class CutoverError(RuntimeError):
    pass

def command(*args,input=None,check=True,timeout=20):
    try:
        p=subprocess.run([str(x) for x in args],input=input,text=True,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise CutoverError("Commande système inaccessible") from exc
    if check and p.returncode:
        raise CutoverError("Commande échouée: "+ " ".join(map(str,args[:4])))
    return p.stdout if check else p

def ensure(condition,message):
    if not condition:raise CutoverError(message)

def json_read(path):
    path=Path(path)
    ensure(path.is_file() and not path.is_symlink() and path.stat().st_size<1_000_000,
           "Fichier Cerato absent/invalide")
    obj=json.loads(path.read_text())
    ensure(isinstance(obj,dict),"État JSON non objet")
    return obj

def atomic(path,contents,mode=0o600):
    path=Path(path)
    fd,tmp=tempfile.mkstemp(prefix=".cerato-routed-",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as f:
            f.write(contents if isinstance(contents,bytes) else contents.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def snapshot_file(path,name):
    target=BASE/name
    ensure(path.is_file() and not path.is_symlink(),"Fichier à sauvegarder absent")
    data=path.read_bytes()
    atomic(target,data,0o600)
    return hashlib.sha256(data).hexdigest()

def address_exists(ip,iface,only32=True):
    raw=json.loads(command("ip","-j","-4","addr","show","dev",iface))
    return any(info.get("local")==ip and (not only32 or info.get("prefixlen")==32)
               for item in raw for info in item.get("addr_info",[])
               if isinstance(info,dict))

def timer_name(role):
    return "cerato-routed-rollback-"+role

def status_path():
    return BASE/"state.json"

def read_state(role):
    obj=json_read(status_path())
    ensure(obj.get("role")==role and obj.get("version")==1,
           "État de migration incompatible")
    return obj

def state_save(obj):
    atomic(status_path(),json.dumps(obj,sort_keys=True,indent=2)+"\n")

def route_public_to_wg():
    raw=json.loads(command("ip","-j","-4","route","get",PUB))
    return len(raw)==1 and raw[0].get("dev")==WG

def wg_peer():
    data=json_read(CFG)
    candidates=[(key,p) for key,p in data.get("peers",{}).items()
                if isinstance(p,dict) and p.get("ip")==VPN]
    ensure(len(candidates)==1,"Le pair WireGuard Dell est ambigu")
    return candidates[0]

def wg_allowed(pubkey):
    for line in command("wg","show",WG,"allowed-ips").splitlines():
        fields=line.split()
        if fields and fields[0]==pubkey:
            return [v.strip(",") for token in fields[1:]
                    for v in token.split(",") if v.strip(",")]
    raise CutoverError("Pair WireGuard introuvable dans le noyau")

def fw_script():
    return ("table ip "+FW_TABLE+" {\n"
            " chain input {\n"
            "  type filter hook input priority -50; policy accept;\n"
            f'  iifname "{WG}" ip daddr {PUB} ct state established,related accept\n'
            f'  iifname "{WG}" ip daddr {PUB} tcp dport 22 accept\n'
            f'  iifname "{WG}" ip daddr {PUB} drop\n'
            " }\n}\n")

def peer_preflight():
    ensure(address_exists("10.77.0.2",WG,only32=False),"IP tunnel Dell absente")
    ensure(not address_exists(PUB,WG),"IPv4 publique déjà attribuée Dell")
    ensure("default dev "+WG in command("ip","-4","route","show","table",TABLE),
           "Route de retour Dell absente")
    rule=command("ip","-4","rule","show")
    ensure(not re.search(r"(?m)^\s*1101:",rule),"Priorité 1101 déjà occupée")
    ensure(re.search(r"(?m)from 10\.77\.0\.2(?:/32)? lookup 51820\b",rule),
           "Règle source VPN existante absente")
    ensure(command("ip","link","show","dev","tailscale0"),
           "Tailscale absent")
    ensure(command("nft","list","table","ip",FW_TABLE,check=False).returncode,
           "Table pare-feu Dell déjà présente")
    ssh=command("/usr/sbin/sshd","-T")
    ensure(all(re.search(r"(?m)^"+k+" "+v+r"$",ssh) for k,v in [
        ("passwordauthentication","no"),("kbdinteractiveauthentication","no"),
        ("pubkeyauthentication","yes"),("permitrootlogin","no")]),
        "SSH par clé uniquement requis")
    output=command("wg","show",WG,"allowed-ips")
    allowed=[]
    for row in output.splitlines():
        parts=row.split()
        if len(parts)<2:continue
        prefixes=[x.strip(",") for x in parts[1:]]
        if any(ipaddress.IPv4Address("10.77.0.1") in ipaddress.ip_network(x,False)
               for x in prefixes if ":" not in x):
            allowed.append(prefixes)
    ensure(len(allowed)==1 and "0.0.0.0/0" in allowed[0],
           "Le pair Dell n'autorise pas l'Internet via WG")

def gateway_preflight():
    ensure(address_exists(PUB,WAN),"L'Additional IP n'est pas sur le WAN")
    ensure(ADMIN in command("ip","-4","addr","show","dev",WAN),
           "Adresse principale OVH absente")
    ensure(command("sysctl","-n","net.ipv4.ip_forward").strip()=="1",
           "Transfert IPv4 OVH inactif")
    cfg=json_read(CFG)
    state=json_read(STATE)
    ensure(PUB in cfg.get("pool",[]),"IP absente du pool")
    ensure(not cfg.get("routed_ipv4"),"Migration routed déjà effectuée")
    old=[x for x in cfg.get("mappings",[]) if x.get("public_ip")==PUB]
    ensure(len(old)==1 and old[0].get("proto")=="tcp" and
           old[0].get("public_port")==8080,
           "Publication NAT historique différente : refus")
    ensure(sum(x.get("ip")==PUB for x in state.get("local_ipv4",[]))==1
           and not state.get("routed_ipv4"),"État persistant Cerato incompatible")
    ensure(cfg.get("wan_if")==WAN and cfg.get("wg_if")==WG,"Interface du contrôleur inconnue")
    ensure(not route_public_to_wg(),"Route publique déjà modifiée")
    ensure(hashlib.sha256(CONTROLLER.read_bytes()).hexdigest()==SOURCE_SHA,
           "Version live de ceratoctl différente")
    name,peer=wg_peer()
    ensure(VPN+"/32" in wg_allowed(peer["pubkey"]),"WireGuard RISE-1 Dell non autorisé")
    return name,peer

def stage_controller():
    # Stage only using the known, previously tested AST transformation.
    source=BASE/"support"/"stage_live_routed_controller.py"
    sys.path.insert(0,str(source.parent))
    from stage_live_routed_controller import transform
    raw=CONTROLLER.read_bytes()
    ensure(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,
           "SHA du contrôleur a changé")
    stage=BASE/"patched"
    stage.mkdir(mode=0o700,exist_ok=False)
    patched=transform(raw)
    ensure(hashlib.sha256(patched).hexdigest()==PATCHED_SHA,
           "Transformateur AST non conforme à la copie RISE-1 validée")
    atomic(stage/"ceratoctl",patched)
    helpers=BASE/"support"
    for src,dst in (("live_routed_compat.py","cerato_routed_support.py"),
                    ("routed_nft_inject.py","routed_nft_inject.py"),
                    ("routed_firewall.py","routed_firewall.py")):
        ensure((helpers/src).is_file(),"Module non trouvé: "+src)
        atomic(stage/dst,(helpers/src).read_bytes())
    return stage

def install_watchdog(role):
    name=timer_name(role)
    deadline=(datetime.datetime.now(datetime.timezone.utc)+
              datetime.timedelta(minutes=DEADLINE_PEER if role=='peer' else DEADLINE_GATEWAY))
    service=(f"[Unit]\nDescription=Cerato routed rollback on {role}\n"
             f"[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {BIN} rollback --role {role}\n")
    timer=(f"[Unit]\nDescription=Cerato routed cutover expiration on {role}\n"
           f"[Timer]\nOnCalendar={deadline.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
           f"AccuracySec=1s\nPersistent=yes\nUnit={name}.service\n"
           "[Install]\nWantedBy=timers.target\n")
    d=Path("/etc/systemd/system")
    ensure(not (d/(name+".timer")).exists(),"Timer rollback du même nom déjà présent")
    atomic(d/(name+".service"),service,0o644)
    atomic(d/(name+".timer"),timer,0o644)
    command("systemctl","daemon-reload")
    command("systemctl","enable","--now",name+".timer")
    ensure(command("systemctl","is-active","--quiet",name+".timer",check=False).returncode==0,
           "Watchdog rollback inactif")
    return deadline.isoformat()

def restore_nft(snapshot):
    raw=snapshot.read_text()
    if command("nft","list","table","ip","cerato_network",check=False).returncode==0:
        raw="delete table ip cerato_network\n"+raw
    command("nft","-f","/dev/stdin",input=raw)

def generate_routed_rules(cfg):
    # Run ONLY the verified render_nft AST function. Never run ceratoctl main.
    stage=BASE/"patched"
    sys.path.insert(0,str(stage))
    import cerato_routed_support
    raw=(stage/"ceratoctl").read_text()
    tree=ast.parse(raw)
    nodes=[x for x in tree.body if isinstance(x,ast.FunctionDef)
           and x.name=="render_nft"]
    ensure(len(nodes)==1,"render_nft absent ou dupliqué")
    safe={
        "__builtins__":{"sorted":sorted,"str":str,"len":len,"ValueError":ValueError},
        "re":re,"ipaddress":ipaddress,
        "routed_render_nft":cerato_routed_support.routed_render_nft,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),
                 "<cerato-renderer>","exec"),safe)
    rules=safe["render_nft"](cfg)
    ensure("table ip cerato_network {" in rules and
           f'ip daddr {PUB} accept' in rules,
           "Règles de routage futures non conformes")
    return rules

def prepare(role,support_dir):
    ensure(os.geteuid()==0,"Root requis")
    ensure(not BASE.exists(),"Préparation existante : statut/rollback avant nouvel essai")
    ensure(BIN.is_file(),"Installer le script dans /usr/local/sbin avant la préparation")
    if role=="peer":peer_preflight()
    else:
        gateway_preflight()
        ensure(all(not (CONTROLLER.parent/item).exists() for item in EXPECTED_SUPPORT),
               "Modules de compatibilité déjà installés : migration inconnue")
    BASE.mkdir(parents=True,mode=0o700)
    try:
        manifest={"version":1,"role":role,"phase":"prepared","deadline":None}
        if role=="gateway":
            snapshot_file(CONTROLLER,"ceratoctl.before")
            snapshot_file(CFG,"config.before")
            snapshot_file(STATE,"managed.before")
            atomic(BASE/"nft.before",command("nft","list","table","ip","cerato_network"))
            name,peer=wg_peer()
            manifest["wg_public_key"]=peer["pubkey"]
            manifest["wg_allowed_before"]=wg_allowed(peer["pubkey"])
            dst=BASE/"support"
            dst.mkdir(mode=0o700)
            for item in (*EXPECTED_SUPPORT,"stage_live_routed_controller.py"):
                src=Path(support_dir)/item
                ensure(src.is_file() and not src.is_symlink(),"Module de déploiement absent")
                contents=src.read_bytes()
                if item in HELPER_SHA:
                    ensure(hashlib.sha256(contents).hexdigest()==HELPER_SHA[item],
                           "Empreinte module Cerato incompatible: "+item)
                atomic(dst/item,contents)
            stage_controller()
            candidate,managed=planned_configs(name)
            rules=generate_routed_rules(candidate)
            atom_rules="delete table ip cerato_network\n"+rules
            atomic(BASE/"nft.routed",atom_rules)
            command("nft","-c","-f",str(BASE/"nft.routed"))
            atomic(BASE/"config.routed",json.dumps(candidate,indent=2,sort_keys=True)+"\n")
            atomic(BASE/"managed.routed",json.dumps(managed,indent=2,sort_keys=True)+"\n")
        else:
            command("nft","-c","-f","/dev/stdin",input=fw_script())
        deadline=install_watchdog(role)
        manifest["deadline"]=deadline
        manifest["phase"]="armed"
        state_save(manifest)
        return {"status":"armed","role":role,"deadline":deadline,
                "network_modified":False}
    except Exception:
        # No network changes have been made by prepare.
        raise

def planned_configs(peer_name):
    cfg=deepcopy(json_read(CFG))
    managed=deepcopy(json_read(STATE))
    nat=[m for m in cfg["mappings"] if m.get("public_ip")==PUB]
    ensure(len(nat)==1,"NAT IP non unique")
    cfg["mappings"]=[m for m in cfg["mappings"] if m.get("public_ip")!=PUB]
    cfg["routed_ipv4"]=[{"ip":PUB,"peer":peer_name}]
    cfg["management_ipv4"]=ADMIN
    existing=[row for row in managed["local_ipv4"] if row.get("ip")==PUB]
    ensure(len(existing)==1,"Alias persistant non trouvé")
    managed["local_ipv4"]=[row for row in managed["local_ipv4"] if row.get("ip")!=PUB]
    managed["routed_ipv4"]=[{"ip":PUB,"peer":peer_name,"wan":WAN}]
    return cfg,managed

def remaining_seconds(info):
    deadline=datetime.datetime.fromisoformat(info["deadline"])
    return (deadline-datetime.datetime.now(datetime.timezone.utc)).total_seconds()

def activate(role):
    info=read_state(role)
    ensure(info["phase"]=="armed","Phase incorrecte")
    ensure(remaining_seconds(info)>600,"Rollback trop proche : refus")
    ensure(command("systemctl","is-active","--quiet",
                   timer_name(role)+".timer",check=False).returncode==0,
           "Watchdog non actif")
    info["phase"]="applying"
    state_save(info)
    try:
        if role=="peer":
            peer_preflight()
            command("nft","-f","/dev/stdin",input=fw_script())
            command("ip","-4","addr","add",PUB+"/32","dev",WG)
            command("ip","-4","rule","add","pref",RULE_PRIORITY,
                    "from",PUB+"/32","table",TABLE)
            route=json.loads(command("ip","-j","-4","route","get","1.1.1.1",
                                     "from",PUB))
            ensure(len(route)==1 and route[0].get("dev")==WG,
                   "Route retour source publique incorrecte")
        else:
            gateway_preflight()
            key=info["wg_public_key"]
            allowed=info["wg_allowed_before"]
            ensure(PUB+"/32" not in allowed,"IPv4 publique déjà dans AllowedIPs")
            command("wg","set",WG,"peer",key,"allowed-ips",
                    ",".join(allowed+[PUB+"/32"]))
            command("ip","-4","route","replace",PUB+"/32","dev",WG)
            # Persisted files + staged controller are installed together as
            # late as possible, then atomic nft table swap and WAN removal.
            for filename in EXPECTED_SUPPORT:
                atomic(CONTROLLER.parent/filename,(BASE/"patched"/filename).read_bytes())
            patched=(BASE/"patched"/"ceratoctl").read_bytes()
            atomic(CONTROLLER,patched,0o755)
            atomic(CFG,(BASE/"config.routed").read_bytes())
            atomic(STATE,(BASE/"managed.routed").read_bytes())
            command("nft","-f",str(BASE/"nft.routed"))
            command("ip","-4","addr","del",PUB+"/32","dev",WAN)
            ensure(route_public_to_wg(),"Route de destination /32 incorrecte")
        info["phase"]="active"
        state_save(info)
        return {"status":"active","role":role,"deadline":info["deadline"],
                "needs_external_verification":True}
    except Exception:
        try:rollback(role)
        except Exception:pass
        raise

def restore_runtime(role):
    if role=="peer":
        rule=command("ip","-4","rule","show",check=False)
        if re.search(r"(?m)^\s*1101:\s+from 54\.37\.165\.151(?:/32)?\s+lookup 51820",rule.stdout):
            command("ip","-4","rule","del","pref",RULE_PRIORITY,
                    "from",PUB+"/32","table",TABLE,check=False)
        if address_exists(PUB,WG):
            command("ip","-4","addr","del",PUB+"/32","dev",WG)
        if command("nft","list","table","ip",FW_TABLE,check=False).returncode==0:
            command("nft","delete","table","ip",FW_TABLE)
    else:
        # Restore configuration FIRST to prevent legacy alias service drift.
        atomic(CFG,(BASE/"config.before").read_bytes())
        atomic(STATE,(BASE/"managed.before").read_bytes())
        atomic(CONTROLLER,(BASE/"ceratoctl.before").read_bytes(),0o755)
        for filename in EXPECTED_SUPPORT:
            module=CONTROLLER.parent/filename
            if module.is_file():module.unlink()
        if not address_exists(PUB,WAN):
            command("ip","-4","addr","add",PUB+"/32","dev",WAN)
        restore_nft(BASE/"nft.before")
        info=read_state(role)
        command("wg","set",WG,"peer",info["wg_public_key"],
                "allowed-ips",",".join(info["wg_allowed_before"]))
        routes=command("ip","-4","route","show",PUB+"/32",check=False)
        if "dev "+WG in routes.stdout:
            command("ip","-4","route","del",PUB+"/32","dev",WG)

def rollback(role):
    info=read_state(role)
    if info['phase']=='committed':
        command('systemctl','disable','--now',UNIT+'-'+role+'.service',check=False)
    errors=[]
    try:restore_runtime(role)
    except Exception as exc:errors.append(str(exc))
    info["phase"]="restored" if not errors else "rollback_failed"
    state_save(info)
    if not errors:
        command("systemctl","disable","--now",timer_name(role)+".timer",check=False)
    return {"status":info["phase"],"role":role,
            "rollback_errors":errors}

def persist(role):
    info=read_state(role)
    ensure(info["phase"]=="active" and remaining_seconds(info)>240,
           "Essai non actif ou rollback proche")
    if role=="peer":
        # Check egress using the new source. No assumptions about full-host
        # default egress: applications must bind PUBLIC for outbound use.
        output=command("curl","-4","-fsS","--connect-timeout","7",
                       "--max-time","12","--interface",PUB,
                       "https://api.ipify.org").strip()
        ensure(output==PUB,"Internet sortant de Dell avec IPv4 publique non confirmé")
    else:
        ensure(not address_exists(PUB,WAN) and route_public_to_wg(),
               "Basculement OVH non actif")
    # Restore is intentionally idempotent and is never a daemon.
    target=Path("/etc/systemd/system")/(UNIT+"-"+role+".service")
    service=(
        "[Unit]\nDescription=Cerato routed public IPv4 restore "+role+"\n"
        "After=network-online.target wg-quick@wg-cerato.service "
        "cerato-network-rules.service cerato-network-additional-ip.service\n"
        "Wants=network-online.target\n\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=on-failure\nRestartSec=10s\n"
        f"ExecStart=/usr/bin/python3 {BIN} restore --role {role}\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    atomic(target,service,0o644)
    command("systemctl","daemon-reload")
    command("systemctl","enable",target.name)
    info["phase"]="committed"
    state_save(info)
    command("systemctl","disable","--now",timer_name(role)+".timer")
    return {"status":"committed","role":role,"persistent_service":target.name,
            "global_default_route_changed":False,
            "note":"Les services doivent écouter sur 0.0.0.0 ou sur l'IPv4 publique. Pour une sortie avec cette IP, l'application doit utiliser cette source."}

def restore(role):
    info=read_state(role)
    ensure(info["phase"]=="committed",
           "Restauration permanente interdite avant validation")
    if role=="peer":
        ensure(bool(command("ip","link","show","dev",WG,check=False).returncode==0),
               "WireGuard Dell indisponible au démarrage")
        if command("nft","list","table","ip",FW_TABLE,check=False).returncode:
            command("nft","-f","/dev/stdin",input=fw_script())
        if not address_exists(PUB,WG):
            command("ip","-4","addr","add",PUB+"/32","dev",WG)
        if "default dev "+WG not in command("ip","-4","route","show","table",TABLE):
            command("ip","-4","route","replace","default","dev",WG,"table",TABLE)
        rule=command("ip","-4","rule","show")
        if not re.search(r"(?m)^\s*1101:\s+from 54\.37\.165\.151(?:/32)?\s+lookup 51820",rule):
            command("ip","-4","rule","add","pref",RULE_PRIORITY,
                    "from",PUB+"/32","table",TABLE)
    else:
        key=info["wg_public_key"]
        current=wg_allowed(key)
        if PUB+"/32" not in current:
            command("wg","set",WG,"peer",key,
                    "allowed-ips",",".join(current+[PUB+"/32"]))
        if not route_public_to_wg():
            command("ip","-4","route","replace",PUB+"/32","dev",WG)
        if address_exists(PUB,WAN):
            command("ip","-4","addr","del",PUB+"/32","dev",WAN)
        # An initial boot can occur before Cerato's nftables table exists.
        # The restored ruleset is generated from the pinned controller.
        rules=(BASE/"nft.routed").read_text()
        if command("nft","list","table","ip","cerato_network",check=False).returncode:
            prefix="delete table ip cerato_network\n"
            ensure(rules.startswith(prefix),"Rendu nft persistant inattendu")
            rules=rules[len(prefix):]
        command("nft","-f","/dev/stdin",input=rules)
    return {"status":"persistent_restored","role":role}

def main():
    parser=argparse.ArgumentParser(description="Cerato routed Additional IPv4 atomic cutover")
    parser.add_argument("action",choices=("prepare","activate","persist","rollback","restore","status"))
    parser.add_argument("--role",choices=("peer","gateway"),required=True)
    parser.add_argument("--support-dir",default=".")
    opt=parser.parse_args()
    if os.geteuid()!=0:parser.error("Root requis")
    try:
        if opt.action=="prepare":report=prepare(opt.role,opt.support_dir)
        elif opt.action=="activate":report=activate(opt.role)
        elif opt.action=="persist":report=persist(opt.role)
        elif opt.action=="rollback":report=rollback(opt.role)
        elif opt.action=="restore":report=restore(opt.role)
        else:report=read_state(opt.role)
        print(json.dumps(report,indent=2,ensure_ascii=False))
    except (CutoverError,ValueError,TypeError,KeyError,OSError) as exc:
        parser.error(str(exc))

if __name__=="__main__":
    main()

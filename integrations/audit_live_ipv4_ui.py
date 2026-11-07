#!/usr/bin/env python3
"""Read-only diagnosis of the already installed Cerato Network 8787 routed IPv4 UI.

Does not execute app/browser code, access authenticated API sessions, modify
networking, or disclose public IPv4, SSH, WireGuard keys or credentials.
Checks the installed ipctl status, the pinned read-only UI model and markers
of the actual backend/front-end; never prints source or raw JSON.
"""
from __future__ import annotations
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys

LIVE=Path("/opt/cerato-network")
IPCTL=Path("/usr/local/sbin/cerato-ipctl")
MODEL=LIVE/"updater/network/routed_ui_status.py"
MAX_BYTES=2_000_000
CHECK_MARKERS={
    "backend_allocations_route": "if p=='/api/ip/allocations'",
    "backend_routed_nat_guard": "cerato_reject_routed_nat(",
    "frontend_ipv4_overlay": "function ceratoEnhanceIPv4()",
    "frontend_ipv4_loader": "async function ceratoLoadIPv4Allocations()",
    "frontend_update_center": "function updates(){",
}
ALLOW_IDS={"app","root","main","content","page","shell","layout","view"}

class SafeHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.has_main=False
        self.ids=set()
        self.script_src=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=="main":
            self.has_main=True
        node_id=attrs.get("id")
        if isinstance(node_id,str) and node_id in ALLOW_IDS:
            self.ids.add(node_id)
        if tag=="script":
            src=attrs.get("src")
            if isinstance(src,str) and src.startswith("/"):
                self.script_src.append(src.split("?",1)[0])

def safe_file(path):
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=MAX_BYTES:
        return None
    try:
        return path.read_text(encoding="utf8")
    except (UnicodeDecodeError,OSError):
        return None

def status_probe(argv):
    try:
        proc=subprocess.run(argv,timeout=15,capture_output=True,text=True,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return {"executed":False,"ok":False,"json_object":False}
    if proc.returncode:
        return {"executed":True,"ok":False,"json_object":False,
                "permission_error":any(s in proc.stderr.lower() for s in (
                    "permission denied","not allowed","password is required","lecture seule"))}
    try:
        obj=json.loads(proc.stdout)
    except ValueError:
        return {"executed":True,"ok":False,"json_object":False}
    return {"executed":True,"ok":isinstance(obj,dict),
            "json_object":isinstance(obj,dict),
            "object":obj if isinstance(obj,dict) else None}

def summarize_source(data):
    if not isinstance(data,dict):
        return {"status":"unavailable"}
    pool=data.get("pool")
    managed=data.get("managed")
    if not isinstance(pool,list) or not isinstance(managed,list):
        return {"status":"invalid"}
    return {"status":"available",
            "pool_size":len(pool),
            "managed_count":len(managed),
            "managed_routed_count":sum(
                row.get("mode")=="routed-wg" for row in managed if isinstance(row,dict))}

def model_probe(model,status):
    if not model or not status:
        return {"validated":False,"reason":"missing_source_or_status"}
    # Import only the pinned pure read-only model shipped with Cerato Network.
    import importlib.util
    spec=importlib.util.spec_from_file_location("cerato_ui_status_diagnostic",MODEL)
    if spec is None or spec.loader is None:
        return {"validated":False,"reason":"model_not_importable"}
    mod=importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        summary=mod.summarize(status)
        return {"validated":True,
                "allocated_count":summary["allocated_count"],
                "routed_count":summary["routed_count"],
                "available_count":summary["available_count"]}
    except (ValueError,KeyError,TypeError,OSError,AttributeError):
        return {"validated":False,"reason":"model_rejected_status"}

def audit(root=LIVE):
    backend=safe_file(root/"backend/server.py")
    frontend=safe_file(root/"web/app.js")
    index=safe_file(root/"web/index.html")
    root_status=status_probe([str(IPCTL),"status"])
    source=summarize_source(root_status.get("object"))
    root_status.pop("object",None)
    # Web calls the privileged IP status helper through sudo; verify exactly
    # this read-only command as the Web service account, without cookies.
    web_status=status_probe(["/usr/sbin/runuser","-u","ceratonet","--",
                             "/usr/bin/sudo","-n",str(IPCTL),"status"])
    web_status.pop("object",None)
    obj={
        "format":"cerato-live-ui-diagnostic-v1",
        "production_modified":False,"network_modified":False,
        "web_service_active":False,
        "ipctl_root":root_status,
        "ipctl_web_service_account":web_status,
        "ipctl_source":source,
        "status_model":model_probe(safe_file(MODEL),status_probe([str(IPCTL),"status"]).get("object")),
        "backend_markers":{},
        "frontend_markers":{},
        "html_anchor":{},
    }
    for mark in ("backend_allocations_route","backend_routed_nat_guard"):
        obj["backend_markers"][mark]=(backend is not None and CHECK_MARKERS[mark] in backend)
    for mark in ("frontend_ipv4_overlay","frontend_ipv4_loader","frontend_update_center"):
        obj["frontend_markers"][mark]=(frontend is not None and CHECK_MARKERS[mark] in frontend)
    if index:
        doc=SafeHTML()
        doc.feed(index)
        obj["html_anchor"]={"found":True,"has_main_element":doc.has_main,
            "has_app_id":"app" in doc.ids,
            "has_root_id":"root" in doc.ids,
            "has_content_id":"content" in doc.ids,
            "script_app_js":"/app.js" in doc.script_src}
    else:
        obj["html_anchor"]={"found":False}
    try:
        p=subprocess.run(["/usr/bin/systemctl","is-active","--quiet",
                          "cerato-network-web.service"],timeout=8)
        obj["web_service_active"]=p.returncode==0
    except (OSError,subprocess.TimeoutExpired):
        pass
    return obj

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--check",action="store_true",required=True)
    parser.parse_args()
    print(json.dumps(audit(),sort_keys=True,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()

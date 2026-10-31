#!/usr/bin/env python3
"""Repair stale update-center UI on the ALREADY INSTALLED RISE-1 app.js.

The original client fetches GET /api/updates only while updateInfo is null.
After first unsuccessful read it retains {configured:false} indefinitely.
Patch just this well-known updater fragment and display API failures distinctly.
No backend, credentials, firewall, service or network actions here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MARKER="/* CERATO-NETWORK-UPDATES-REFRESH-V1 */"
NAV="let updateInfo=null,updateLoading=false;"
ERROR="""    updateInfo={configured:false,installable:false,
      last_result:error.message||'Impossible de lire les mises à jour'};"""
ERROR_REPLACEMENT="""    updateInfo={configured:false,installable:false,
      reason_code:'web_api_unavailable',
      last_result:error.message||'Impossible de lire les mises à jour'};"""
STATUS="""    !configured?'Distribution à configurer':"""
STATUS_REPLACEMENT="""    reason==='web_api_unavailable'?'API mises à jour indisponible':
    !configured?'Distribution à configurer':"""
DESCRIPTION="""  const description=!configured
    ?'Le serveur ne dispose pas encore d’une source HTTPS officielle et de sa clé de vérification. La configuration initiale se fait une seule fois par un administrateur système.'
    :(u.last_result||'La vérification des mises à jour n’a pas encore été effectuée.');"""
DESCRIPTION_REPLACEMENT="""  const description=!configured
    ? (reason==='web_api_unavailable'
        ? (u.last_result||'Impossible de joindre le service de mises à jour.')
        : 'Le serveur ne dispose pas encore d’une source HTTPS officielle et de sa clé de vérification. La configuration initiale se fait une seule fois par un administrateur système.')
    : (u.last_result||'La vérification des mises à jour n’a pas encore été effectuée.');"""

NAV_REFRESH=r"""
/* CERATO-NETWORK-UPDATES-REFRESH-V1 */
// Discard stale cached status BEFORE the existing navigation click handler runs.
document.addEventListener('click',function(event){
  const target=event.target.closest('[data-screen="updates"]');
  if(target)updateInfo=null;
},true);
// The UI may stay open while the signed-release mirror updates its channel.
window.addEventListener('focus',function(){
  if(screen==='updates'&&!updateLoading)refreshUpdateInfo();
});
document.addEventListener('visibilitychange',function(){
  if(!document.hidden&&screen==='updates'&&!updateLoading)refreshUpdateInfo();
});
setInterval(function(){
  if(screen==='updates'&&!document.hidden&&!updateLoading)refreshUpdateInfo();
},60000);
"""

class UpdateRefreshError(ValueError):
    pass


def patch(source:str)->str:
    if MARKER in source:
        raise UpdateRefreshError("Correctif de rafraîchissement déjà installé")
    required={
        NAV:1,
        ERROR:1,
        STATUS:1,
        DESCRIPTION:1,
        "function updates(){":1,
        "function render(){if(!live)return;":1,
        "async function refreshUpdateInfo(){":1,
        "updateInfo=await req('/api/updates');":1,
        "if(screen==='updates')render();":2, # refresh + check handler
    }
    for fragment,count in required.items():
        if source.count(fragment)!=count:
            raise UpdateRefreshError("Version de l'interface inattendue, intervention refusée : "+fragment[:65])
    result=source.replace(NAV,NAV+"\n"+NAV_REFRESH,1)
    result=result.replace(ERROR,ERROR_REPLACEMENT,1)
    result=result.replace(STATUS,STATUS_REPLACEMENT,1)
    result=result.replace(DESCRIPTION,DESCRIPTION_REPLACEMENT,1)
    if (result.count(MARKER)!=1 or result.count("function updates(){")!=1
            or result.count("function render(){if(!live)return;")!=1):
        raise UpdateRefreshError("Modification du frontend incohérente")
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--destination",required=True,type=Path)
    args=parser.parse_args()
    src=args.source;dest=args.destination
    if src.is_symlink() or not src.is_file() or dest.exists() or dest.is_symlink():
        parser.error("Source ou destination non sûre")
    try:
        result=patch(src.read_text(encoding="utf8"))
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(result,encoding="utf8")
        print(json.dumps({"updated":"web/app.js","frontend_only":True,
                          "api_route_unchanged":True,"network_modified":False,
                          "source_bytes":src.stat().st_size,
                          "output_bytes":dest.stat().st_size}))
    except (ValueError,OSError,UnicodeError) as exc:
        parser.error(str(exc))


if __name__=="__main__":
    main()

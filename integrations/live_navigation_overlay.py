"""Pinpoint an inactive hash-navigation layer for the real legacy 8787 JS.

Only used when preparing a PRIVATE frontend candidate. Does not alter the
live UI or store sessions/credentials in browser storage.
"""
from __future__ import annotations

class NavigationStageError(ValueError):
    pass

MARKER="CERATO_LEGACY_NAV_PERSISTENCE_V1"
ANCHOR="function render(){if(!live)return;"
SCREENS=("overview","ips","machines","nat","firewall",
         "topology","logs","settings","updates")
CODE="""/* CERATO_LEGACY_NAV_PERSISTENCE_V1 — URL hash only, no storage. */
const ceratoNavigationScreens=new Set([
  'overview','ips','machines','nat','firewall','topology','logs','settings','updates'
]);
let ceratoNavigationBooted=false;
function ceratoNavigationRoute(){
  const hash=window.location.hash;
  if(!hash.startsWith('#/'))return null;
  const view=hash.slice(2);
  return ceratoNavigationScreens.has(view)?view:null;
}
function ceratoNavigationSync(){
  if(!ceratoNavigationBooted){
    ceratoNavigationBooted=true;
    const saved=ceratoNavigationRoute();
    if(saved)screen=saved;
    return;
  }
  if(ceratoNavigationScreens.has(screen)&&window.location.hash!=='#/'+screen){
    window.history.replaceState(null,'','#/'+screen);
  }
}
function ceratoNavigationRestore(){
  if(!ceratoNavigationBooted)return;
  const saved=ceratoNavigationRoute();
  if(saved && saved!==screen){
    screen=saved;
    render();
  }
}
window.addEventListener('hashchange',ceratoNavigationRestore);
window.addEventListener('popstate',ceratoNavigationRestore);
"""

def apply(source:str)->str:
    if not isinstance(source,str) or source.count(ANCHOR)!=1:
        raise NavigationStageError("Ancrage de navigation historique incompatible")
    if MARKER in source:
        raise NavigationStageError("Navigation déjà préparée")
    for name in SCREENS:
        if not (f"'{name}'" in source or f'"{name}"' in source):
            raise NavigationStageError("Section du panneau absente")
    patched=source.replace(
        ANCHOR,
        CODE+"\n"+ANCHOR+"\n  ceratoNavigationSync();",
        1)
    compile_source=patched.encode("utf8")
    if len(compile_source)>2_000_000:
        raise NavigationStageError("JavaScript candidat trop volumineux")
    return patched

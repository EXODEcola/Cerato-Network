#!/usr/bin/env python3
"""Attach a real signed-release center to the existing Cerato Web (8787).

Conservatively patches the CURRENT legacy console source. Does not replace its
network, NAT or WireGuard backend; rejects unfamiliar layouts. API calls
fixed, root-owned scripts via exact sudoers entries. No user-chosen commands,
URLs or paths can be passed to the update controller.
"""
from pathlib import Path
import argparse
import re


class UpgradePatchError(Exception):
    pass


SERVER_HELPER='''
def live_update(*args):
    # The Web client cannot pass arbitrary arguments or supply a release URL.
    allowed={'status','check'}
    if len(args)!=1 or args[0] not in allowed:
        raise UserError('Action de mise à jour interdite.')
    try:
        result=subprocess.run(['sudo','-n','/usr/local/sbin/cerato-updatectl',args[0]],
                              capture_output=True,text=True,timeout=50,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise UserError('Service de mises à jour indisponible.')
    if result.returncode:
        raise UserError('Centre de mises à jour indisponible. Vérifier le service de contrôle.')
    return json.loads(result.stdout)

def launch_signed_update():
    # systemd holds the privileged worker beyond this HTTP request and the
    # restart of the existing Web service. Never run arbitrary shell commands.
    try:
        result=subprocess.run(
            ['sudo','-n','/usr/bin/systemctl','start','--no-block',
             'cerato-network-update.service'],
            capture_output=True,text=True,timeout=6,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise UserError('Impossible de démarrer le service de mise à jour.')
    if result.returncode:
        raise UserError('Service de mise à jour refusé.')
'''

GET_ROUTE="""                if p=='/api/updates': return self.send_json(200,live_update('status'))
"""

POST_ROUTES="""            if p=='/api/updates/check':
                result=live_update('check')
                audit('updates-check','Vérification des releases signées')
                return self.send_json(200,result)
            if p=='/api/updates/install':
                current=live_update('status')
                if not current.get('installable'):
                    raise UserError('Aucune version signée et compatible à installer.')
                launch_signed_update()
                audit('updates-install','Installation signée demandée')
                return self.send_json(202,{'ok':True,'message':'Installation demandée. Vérification et retour arrière surveillés.'})
"""


def patch_backend(source:str)->str:
    if 'def live_update(' in source:
        raise UpgradePatchError('Centre de mises à jour déjà installé.')
    anchor='def netstate():'
    if source.count(anchor)!=1:
        raise UpgradePatchError('Source du panneau inconnu : netstate introuvable')
    source=source.replace(anchor,SERVER_HELPER+'\n'+anchor)
    # Preserve the exact indentation found on the installed handler. Legacy
    # variants differ (12 vs 16 spaces) but the route expression must match.
    get_pattern=re.compile(
        r"^(?P<indent> {8,24})if p=='/api/status': return self\.send_json\(200,netstate\(\)\)[ \t]*$",
        re.MULTILINE,
    )
    matches=list(get_pattern.finditer(source))
    if len(matches)!=1:
        raise UpgradePatchError('Handler GET actuel incompatible')
    indent=matches[0].group('indent')
    get_anchor=matches[0].group(0)
    inserted=indent+"if p=='/api/updates': return self.send_json(200,live_update('status'))\n"+get_anchor
    source=source.replace(get_anchor,inserted,1)
    post_anchor="            if p=='/api/peers':"
    if source.count(post_anchor)!=1 or "if not self.check_session(write=True)" not in source:
        raise UpgradePatchError('Handler POST ou protection CSRF incompatible')
    source=source.replace(post_anchor,POST_ROUTES+post_anchor)
    return source


UPDATES_JS=r"""
function updates(){
  const u=updateInfo||{};
  const configured=Boolean(u.configured);
  const ready=Boolean(configured&&u.installable);
  const version=esc(u.installed_version||'Installation historique');
  const available=esc(u.available_version||'Aucune');
  const channel=esc(u.channel==='beta'?'Bêta':u.channel==='stable'?'Stable':'Non défini');
  const checkTime=u.last_checked_at?new Date(u.last_checked_at*1000).toLocaleString('fr-FR'):'Jamais';
  const reason=u.reason_code||'';
  const statusText=ready?'Prête à installer':
    !configured?'Distribution à configurer':
    reason==='already_current'?'À jour':
    reason==='release_not_compatible'?'Version incompatible':
    reason==='release_check_failed'?'Vérification échouée':
    'Aucune installation disponible';
  const stateClass=ready?'ok':reason==='release_check_failed'?'error':configured?'neutral':'warning';
  const description=!configured
    ?'Le serveur ne dispose pas encore d’une source HTTPS officielle et de sa clé de vérification. La configuration initiale se fait une seule fois par un administrateur système.'
    :(u.last_result||'La vérification des mises à jour n’a pas encore été effectuée.');
  const history=(u.history||[]).slice(-8).reverse().map(x=>
    '<tr><td>'+esc(x.version||'-')+'</td><td>'+
    (x.time?new Date(x.time*1000).toLocaleString('fr-FR'):'-')+
    '</td><td>'+esc(x.snapshot?'Disponible':'Non remontée')+'</td></tr>').join('');
  return '<div class="cerato-updates">'+
    '<div class="cerato-update-header">'+
      '<div><div class="cerato-eyebrow">SYSTÈME / MAINTENANCE</div>'+
      '<h2>Mises à jour</h2><p>Versions compatibles et distribution signée Cerato Network.</p></div>'+
      '<div class="cerato-update-actions"><button class="btn2" id="updates-check" '+
      (configured?'':'disabled')+'>Rechercher une mise à jour</button></div></div>'+
    '<div class="cerato-update-summary">'+
      '<div><small>Version installée</small><strong>'+version+'</strong></div>'+
      '<div><small>Version disponible</small><strong>'+available+'</strong></div>'+
      '<div><small>Canal</small><strong>'+channel+'</strong></div>'+
      '<div><small>Dernière vérification</small><strong>'+esc(checkTime)+'</strong></div></div>'+
    '<div class="cerato-update-panel">'+
      '<div class="cerato-update-panel-head"><h3>Distribution et intégrité</h3>'+
      '<span class="cerato-update-state '+stateClass+'">'+esc(statusText)+'</span></div>'+
      '<p class="cerato-update-description">'+esc(description)+'</p>'+
      '<div class="cerato-update-facts">'+
        '<span><b>Source HTTPS</b><em>'+ (configured?'Configurée':'Non configurée') +'</em></span>'+
        '<span><b>Signature</b><em>Ed25519 obligatoire</em></span>'+
        '<span><b>Compatibilité</b><em>Console RISE-1 / 8787</em></span></div>'+
      '<div class="cerato-update-install">'+
        '<button class="btn2 primary" id="updates-install" '+(ready?'':'disabled')+
        '>Installer la version vérifiée</button>'+
        '<span>Une installation conserve les configurations réseau et sauvegarde la version Web précédente.</span></div>'+
    '</div>'+
    '<div class="cerato-update-panel"><div class="cerato-update-panel-head">'+
      '<h3>Historique des installations</h3></div>'+
      table(['Version','Date','Sauvegarde'],history)+
      (!history?'<p class="cerato-update-description">Aucune mise à jour enregistrée.</p>':'')+
    '</div></div>';
}
"""

def patch_frontend(source:str)->str:
    if "function updates(){" in source or "['updates','Mises à jour'" in source:
        raise UpgradePatchError('Centre des mises à jour déjà présent.')
    nav_anchor="['settings','Configuration','settings']"
    if source.count(nav_anchor)!=1:
        raise UpgradePatchError('Sidebar historique incompatible')
    source=source.replace(nav_anchor,nav_anchor+",['updates','Mises à jour','settings']")
    # The existing RISE-1 UI has evolved independently of the development
    # fixture. Do NOT rewrite its screen-to-function table; injecting into
    # the verified render boundary preserves every existing page.
    render_anchor="function render(){if(!live)return;"
    if source.count(render_anchor)!=1:
        raise UpgradePatchError('Rendu du panneau incompatible')
    if "function bind(" not in source or "shell(" not in source:
        raise UpgradePatchError('Fonctions shell/bind du panneau introuvables')
    # Attach click handlers using delegation: the original bind() function
    # can vary without causing brittle code replacements.
    interactivity=r"""
let updateInfo=null,updateLoading=false;
async function refreshUpdateInfo(){
  if(updateLoading)return;
  updateLoading=true;
  try{
    updateInfo=await req('/api/updates');
  }catch(error){
    updateInfo={configured:false,installable:false,
      last_result:error.message||'Impossible de lire les mises à jour'};
  }finally{
    updateLoading=false;
    if(screen==='updates')render();
  }
}
document.addEventListener('click',async function(event){
  const button=event.target.closest('#updates-check,#updates-install');
  if(!button)return;
  event.preventDefault();
  if(button.id==='updates-check'){
    if(updateLoading)return;
    updateLoading=true;
    button.disabled=true;
    try{
      updateInfo=await req('/api/updates/check','POST',{});
      toast(updateInfo.installable?'Release signée compatible prête.':updateInfo.last_result||'Aucune release compatible.');
    }catch(error){
      toast(error.message,true);
    }finally{
      updateLoading=false;
      if(screen==='updates')render();
    }
    return;
  }
  if(!updateInfo?.installable)return;
  if(!window.confirm('Installer la release signée '+updateInfo.available_version+
    ' ? Le panneau redémarrera; les tunnels existants seront conservés.'))return;
  button.disabled=true;
  try{
    const response=await req('/api/updates/install','POST',{});
    toast(response.message||'Mise à jour lancée');
    updateInfo.installable=false;
    render();
    setTimeout(()=>location.reload(),12000);
  }catch(error){
    toast(error.message,true);
    button.disabled=false;
  }
},true);
"""
    # render() calls shell() and bind() the same way as existing screens,
    # but leaves the legacy navigation and all its other routes untouched.
    screen_override="""function render(){if(!live)return;
  if(screen==='updates'){
    if(!updateInfo&&!updateLoading){
      Promise.resolve().then(refreshUpdateInfo);
    }
    shell(updates());
    bind();
    return;
  }
"""
    source=source.replace(render_anchor,interactivity+"\n"+UPDATES_JS+"\n"+screen_override)
    return source


def patch_tree(base:Path,destination:Path):
    backend=base/"backend/server.py"
    frontend=base/"web/app.js"
    if base.resolve()==destination.resolve() or not backend.is_file() or not frontend.is_file():
        raise UpgradePatchError('Chemins de patch invalides')
    server=patch_backend(backend.read_text(encoding="utf8"))
    app=patch_frontend(frontend.read_text(encoding="utf8"))
    for rel,data in (("backend/server.py",server),("web/app.js",app)):
        target=destination/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(data,encoding="utf8")
    return {"backend_bytes":len(server),"frontend_bytes":len(app)}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--destination",required=True,type=Path)
    args=parser.parse_args()
    try:
        print(patch_tree(args.source,args.destination))
    except (OSError,UpgradePatchError,UnicodeError) as exc:
        parser.error(str(exc))

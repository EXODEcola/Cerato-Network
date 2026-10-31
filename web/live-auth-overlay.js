/* Cerato Network — self-contained native login for the historic 8787 console.
   Deployment requires an authenticated backend, proper reverse proxy and
   end-to-end approval. Never depend on hiding controls for authorization. */
(function () {
  'use strict';
  const ROOT_ID='cerato-native-auth';
  const state={account:null, csrf:'', challenge:null, active:false};
  const endpoint='/api/auth/';
  const label={owner:'Propriétaire',admin:'Administrateur',user:'Lecture seule'};
  function element(tag,className,text) {
    const el=document.createElement(tag);
    if(className)el.className=className;
    if(text !== undefined)el.textContent=String(text);
    return el;
  }
  function control(name,type,value,autocomplete) {
    const wrap=element('label','cerato-auth-field');
    const title=element('span','',name);
    const input=element('input','');
    input.type=type; input.placeholder=value||''; input.required=true;
    if(autocomplete)input.autocomplete=autocomplete;
    wrap.append(title,input);
    return {wrap,input};
  }
  function button(text,fn,kind) {
    const b=element('button','cerato-auth-button'+(kind?' '+kind:''),text);
    b.type='button';
    b.addEventListener('click',fn);
    return b;
  }
  async function call(path,method='GET',body) {
    const headers={'Accept':'application/json'};
    if(body !== undefined)headers['Content-Type']='application/json';
    if(method !== 'GET' && state.csrf)headers['X-Cerato-CSRF']=state.csrf;
    const response=await fetch(path,{method,headers,credentials:'same-origin',
      body:body===undefined?undefined:JSON.stringify(body),
      cache:'no-store',redirect:'error'});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw Error(data.error||('Erreur HTTP '+response.status));
    return data;
  }
  function overlay(heading,subtitle) {
    let root=document.getElementById(ROOT_ID);
    if(!root){root=element('div','cerato-auth-overlay');root.id=ROOT_ID;document.body.append(root);}
    root.replaceChildren();
    const panel=element('div','cerato-auth-dialog');
    panel.setAttribute('role','dialog');
    panel.setAttribute('aria-modal','true');
    panel.setAttribute('aria-label',heading);
    const emblem=element('span','cerato-auth-emblem','◇ CERATO NETWORK');
    panel.append(emblem,element('h1','',heading),element('p','cerato-auth-subtitle',subtitle));
    root.append(panel);
    return panel;
  }
  function errorMessage(box,err) {
    let status=box.querySelector('.cerato-auth-error');
    if(!status){status=element('p','cerato-auth-error');status.setAttribute('role','alert');box.append(status);}
    status.textContent=err&&err.message||'Opération refusée.';
  }
  function action(form,caption,submit) {
    const b=button(caption,async()=>{
      const values=form.map(field=>field.input.type==='password'
        ?field.input.value:field.input.value.trim());
      if(!values.every(value=>value.length>0))return;
      b.disabled=true;
      try{await submit(values);}
      catch(e){errorMessage(b.closest('.cerato-auth-dialog'),e);}
      finally{b.disabled=false;}
    },'primary');
    return b;
  }
  function firstLogin(initialized) {
    state.active=true;
    state.account=null;
    const panel=overlay(initialized?'Connexion':'Créer le compte propriétaire',
      initialized?'E-mail, mot de passe et vérification forte pour les administrateurs.':
      'Un code d’initialisation temporaire doit être généré depuis la console serveur.');
    const fields=initialized?
      [control('Adresse e-mail','email','admin@exemple.fr','username'),
       control('Mot de passe','password','Mot de passe','current-password')]:
      [control('Code d’initialisation','text','Code à usage unique','off'),
       control('Adresse e-mail principale','email','admin@exemple.fr','username'),
       control('Mot de passe','password','14 caractères minimum','new-password')];
    fields.forEach(f=>panel.append(f.wrap));
    panel.append(action(fields,initialized?'Se connecter':'Créer le propriétaire',async values=>{
      if(initialized){
        const result=await call(endpoint+'login','POST',{email:values[0],password:values[1]});
        if(result.mfa_required)return renderMfa(result);
        state.account=result.account;state.csrf=result.csrf;
        return sessionReady();
      }
      await call(endpoint+'setup','POST',{token:values[0],email:values[1],password:values[2]});
      firstLogin(true);
    }));
  }
  function renderMfa(result) {
    state.challenge=result.challenge;
    const setup=Boolean(result.mfa_setup);
    const panel=overlay(setup?'Configurer la double authentification':'Vérification 2FA',
      setup?'Configure ton application TOTP, puis valide un code à six chiffres.':
      'Code TOTP à six chiffres ou code de récupération à usage unique.');
    if(setup){
      panel.append(element('span','cerato-auth-hint','Clé TOTP à conserver uniquement dans ton application'));
      const secret=element('code','cerato-auth-secret',result.otp_secret||'');
      panel.append(secret);
      if(result.otp_uri){
        const link=element('a','cerato-auth-link','Ouvrir dans une application compatible');
        link.href=result.otp_uri;panel.append(link);
      }
    }
    const field=control('Code de vérification','text','000000','one-time-code');
    field.input.inputMode='numeric';
    panel.append(field.wrap,action([field],'Vérifier et continuer',async ([code])=>{
      const verified=await call(endpoint+'mfa/verify','POST',{challenge:state.challenge,code});
      state.account=verified.account;state.csrf=verified.csrf;state.challenge=null;
      if(verified.recovery_codes)return showRecovery(verified.recovery_codes);
      sessionReady();
    }));
    panel.append(button('Retour',()=>firstLogin(true)));
  }
  function showRecovery(codes){
    const panel=overlay('Codes de récupération','À sauvegarder maintenant : ils ne seront plus affichés.');
    panel.append(element('pre','cerato-auth-secret',codes.join('\n')));
    panel.append(button('Copier les codes',()=>{
      navigator.clipboard.writeText(codes.join('\n')).catch(e=>errorMessage(panel,e));
    }));
    panel.append(button('J’ai enregistré mes codes',()=>sessionReady(),'primary'));
  }
  function sessionReady() {
    document.getElementById(ROOT_ID)?.remove();
    state.active=false;
    // Loading the legacy app is its responsibility. Refreshing re-evaluates
    // its existing /api/session and /api/status handlers using the new cookie.
    location.reload();
  }
  async function accounts() {
    const panel=overlay('Comptes et permissions','Gestion des accès au routeur Cerato Network.');
    const result=await call('/api/accounts');
    const listing=element('div','cerato-account-list');
    (result.accounts||[]).forEach(acc=>{
      const item=element('div','cerato-account-row');
      const description=element('span','',acc.email+' · '+(label[acc.role]||acc.role));
      item.append(description);
      if(acc.role!=='owner' && acc.id!==state.account.id){
        item.append(button(acc.active?'Désactiver':'Réactiver',async()=>{
          if(!confirm('Modifier l’accès de '+acc.email+' ?'))return;
          await call('/api/accounts/'+acc.id,'PATCH',{active:!acc.active});
          await accounts();
        }));
      }
      listing.append(item);
    });
    panel.append(listing);
    const email=control('E-mail du nouveau compte','email','compte@exemple.fr','off');
    const password=control('Mot de passe initial','password','14 caractères minimum','new-password');
    const role=element('select','cerato-auth-select');
    for(const [value,text] of [['user','Utilisateur — lecture seule'],['admin','Administrateur']]){
      const op=element('option','',text);op.value=value;role.append(op);
    }
    const row=element('label','cerato-auth-field','Rôle');
    row.append(role);
    panel.append(email.wrap,password.wrap,row);
    const add=button('Créer le compte',async()=>{
      try{
        add.disabled=true;
        await call('/api/accounts','POST',{email:email.input.value.trim(),
          password:password.input.value,role:role.value});
        await accounts();
      }catch(err){errorMessage(panel,err);}
      finally{add.disabled=false;}
    },'primary');
    panel.append(add,button('Fermer',()=>document.getElementById(ROOT_ID)?.remove()));
  }
  function accessActions(){
    if(!state.account || state.active)return;
    const target=document.querySelector('.topbar,.top-bar,header.topbar')||document.querySelector('header');
    if(!target || document.getElementById('cerato-account-actions'))return;
    const box=element('div','cerato-account-actions');box.id='cerato-account-actions';
    if(state.account.role!=='user')box.append(button('Comptes et accès',()=>{
      accounts().catch(err=>errorMessage(overlay('Erreur d’accès',''),err));
    }));
    box.append(button('Déconnexion',async()=>{
      try{await call(endpoint+'logout','POST',{});}
      finally{state.account=null;state.csrf='';location.reload();}
    }));
    target.append(box);
  }
  document.addEventListener('click',event=>{
    const btn=event.target.closest('button');
    if(!btn||btn.closest('#cerato-account-actions')||btn.closest('#'+ROOT_ID))return;
    if(btn.textContent.trim().toLowerCase()==='déconnexion'){
      event.preventDefault();event.stopImmediatePropagation();
      call(endpoint+'logout','POST',{}).finally(()=>location.reload());
    }
  },true);
  async function initialize(){
    try{
      const session=await call(endpoint+'me');
      state.account=session.account;state.csrf=session.csrf;
      accessActions();
      const observer=new MutationObserver(accessActions);
      observer.observe(document.body,{subtree:true,childList:true});
    }catch(_){
      try{
        const setup=await call(endpoint+'setup-status');
        firstLogin(Boolean(setup.initialized));
      }catch(err){
        errorMessage(overlay('Service de connexion indisponible',
          'Le contrôle des comptes ne répond pas. L’ancienne protection reste obligatoire.'),err);
      }
    }
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initialize,{once:true});
  else initialize();
})();

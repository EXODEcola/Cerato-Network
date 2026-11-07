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
  // Preserve legacy network mutations while the server enforces the native
  // same-origin cookie, role and CSRF checks. Scoped to same-origin /api/*
  // writes only. This remains inactive until the migration is approved.
  let transportInstalled=false;
  function installNativeTransport(){
    if(transportInstalled || !state.account || !state.csrf)return;
    const nativeFetch=window.fetch.bind(window);
    window.fetch=function(input,init){
      const opts=init||{};
      const method=String(opts.method||input?.method||'GET').toUpperCase();
      let url;
      try{
        const target=typeof input==='string'?input:input?.url;
        if(typeof target==='string')url=new URL(target,window.location.href);
      }catch(_){return nativeFetch(input,init);}
      if(url && url.origin===window.location.origin &&
        url.pathname.startsWith('/api/') &&
        ['POST','PUT','PATCH','DELETE'].includes(method) && state.csrf){
        const headers=new Headers(opts.headers||input?.headers||{});
        if(!headers.has('X-Cerato-CSRF'))headers.set('X-Cerato-CSRF',state.csrf);
        return nativeFetch(input,{...opts,headers,credentials:'same-origin'});
      }
      return nativeFetch(input,init);
    };
    transportInstalled=true;
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
    form.forEach(field=>field.input.addEventListener('keydown',event=>{
      if(event.key==='Enter'){event.preventDefault();b.click();}
    }));
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
      const detail=acc.role==='user'?'Lecture seule':
        (acc.mfa_enabled?'MFA actif':'MFA à configurer');
      const count=Number.isInteger(acc.active_sessions)?
        ' · '+acc.active_sessions+' session(s) active(s)':'';
      const description=element('span','',
        acc.email+' · '+(label[acc.role]||acc.role)+' · '+detail+count);
      item.append(description);
      if(acc.role!=='owner' && acc.id!==state.account.id){
        item.append(button(acc.active?'Désactiver':'Réactiver',async()=>{
          if(!confirm('Modifier l’accès de '+acc.email+' ?'))return;
          await call('/api/accounts/'+acc.id,'PATCH',{active:!acc.active});
          await accounts();
        }));
        if(acc.role==='admin'){
          item.append(button('Réinitialiser MFA',async()=>{
            if(!confirm('Réinitialiser la double authentification de '+acc.email+
              ' ? Toutes les sessions de ce compte seront révoquées.'))return;
            try{
              await call('/api/accounts/'+acc.id,'PATCH',{reset_mfa:true});
              await accounts();
            }catch(err){errorMessage(panel,err);}
          }));
        }
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
  function myAccount(){
    if(!state.account)return;
    const panel=overlay('Mon compte','Modifier mes identifiants. La session sera révoquée après modification.');
    panel.append(element('p','cerato-auth-subtitle',
      state.account.email+' · '+(label[state.account.role]||state.account.role)));
    const current=control('Mot de passe actuel','password',
      'Mot de passe actuel','current-password');
    const email=control('Nouvelle adresse e-mail (facultatif)','email',
      'Laisser vide pour conserver','email');
    email.input.required=false;
    const password=control('Nouveau mot de passe (facultatif)','password',
      '14 caractères minimum','new-password');
    password.input.required=false;
    panel.append(current.wrap,email.wrap,password.wrap);
    const save=button('Enregistrer mes identifiants',async()=>{
      if(!current.input.value)return;
      if(!email.input.value.trim()&&!password.input.value){
        errorMessage(panel,new Error('Indique une adresse e-mail ou un nouveau mot de passe.'));
        return;
      }
      save.disabled=true;
      try{
        const body={current_password:current.input.value};
        if(email.input.value.trim())body.email=email.input.value.trim();
        if(password.input.value)body.new_password=password.input.value;
        await call(endpoint+'me','PATCH',body);
        state.account=null;state.csrf='';
        location.reload();
      }catch(err){errorMessage(panel,err);}
      finally{save.disabled=false;}
    },'primary');
    panel.append(save,button('Fermer',()=>document.getElementById(ROOT_ID)?.remove()));
  }
  function accessActions(){
    if(!state.account || state.active)return;
    const target=document.querySelector('.topbar,.top-bar,header.topbar')||document.querySelector('header');
    if(!target || document.getElementById('cerato-account-actions'))return;
    const box=element('div','cerato-account-actions');box.id='cerato-account-actions';
    if(state.account.role!=='user')box.append(button('Comptes et accès',()=>{
      accounts().catch(err=>errorMessage(overlay('Erreur d’accès',''),err));
    }));
    box.append(button('Mon compte',myAccount));
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
      installNativeTransport();
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

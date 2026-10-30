'use strict';

/* Cerato Network — standalone development console.
 * All privileged permission checks happen on the server, never in this file.
 */
const app = document.getElementById('app');
const state = { account: null, csrf: '', view: 'dashboard', status: null, accounts: [], updateInfo: null };

function node(tag, className, textValue) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (textValue !== undefined && textValue !== null) el.textContent = String(textValue);
  return el;
}
function child(parent, ...children) {
  children.forEach(el => { if (el) parent.appendChild(el); });
  return parent;
}
function button(label, action, css = '') {
  const b = node('button', css || 'button', label);
  b.type = 'button';
  b.addEventListener('click', action);
  return b;
}
function input(label, name, type, placeholder, required = true) {
  const line = node('label', 'field');
  const span = node('span', 'field-label', label);
  const el = node('input', 'textinput');
  el.name = name;
  el.type = type;
  el.placeholder = placeholder || '';
  el.required = required;
  el.autocomplete = name === 'email' ? 'email' : 'off';
  line.append(span, el);
  return line;
}
function select(label, name, items) {
  const line = node('label', 'field');
  const sp = node('span', 'field-label', label);
  const sel = node('select', 'textinput');
  sel.name = name;
  items.forEach(([value, display]) => {
    const option = node('option', '', display);
    option.value = value;
    sel.appendChild(option);
  });
  return child(line, sp, sel);
}
function paragraph(text, css) { return node('p', css || 'hint', text); }
function notify(text, error = false) {
  let notice = document.getElementById('notice');
  if (!notice) { notice = node('div', 'notice'); document.body.appendChild(notice); }
  notice.textContent = text;
  notice.className = 'notice' + (error ? ' error' : '');
}
async function api(path, method = 'GET', payload = null) {
  const opts = { method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
  if (payload !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(payload);
  }
  if (!['GET', 'HEAD'].includes(method) && state.csrf) opts.headers['X-Cerato-CSRF'] = state.csrf;
  let response;
  try { response = await fetch(path, opts); }
  catch (_) { throw Error('Connexion avec la passerelle impossible.'); }
  const json = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(json.error || ('Erreur HTTP ' + response.status));
  return json;
}
function form(title, description, controls, submitName, submit) {
  const panel = node('section', 'form-panel');
  const heading = node('h1', '', title);
  const desc = paragraph(description);
  const fields = node('form', 'form');
  controls.forEach(c => fields.appendChild(c));
  const action = node('button', 'button primary', submitName);
  action.type = 'submit';
  fields.appendChild(action);
  fields.addEventListener('submit', async ev => {
    ev.preventDefault();
    action.disabled = true;
    const data = Object.fromEntries(new FormData(fields).entries());
    try { await submit(data); }
    catch (err) { notify(err.message, true); }
    finally { action.disabled = false; }
  });
  panel.append(heading, desc, fields);
  return panel;
}
function renderUnauth(initialized) {
  state.account = null;
  app.replaceChildren();
  const wrap = node('main', 'auth-layout');
  const brand = node('div', 'auth-brand', '◈  CERATO NETWORK');
  const detail = node('div', 'auth-sub', 'Console de gestion réseau sécurisée');
  let panel;
  if (!initialized) {
    panel = form('Configuration initiale',
      'Le compte principal est créé une seule fois. Obtiens d’abord un code temporaire depuis la console SSH du serveur.',
      [input('Code d’initialisation SSH', 'token', 'text', 'Code à usage unique'),
       input('Adresse e-mail principale', 'email', 'email', 'admin@exemple.fr'),
       input('Mot de passe (14 caractères minimum)', 'password', 'password', 'Mot de passe'),
       input('Confirmation', 'confirmation', 'password', 'Confirmer')],
      'Créer le compte principal', async d => {
        if (d.password !== d.confirmation) throw Error('Les mots de passe sont différents.');
        await api('/api/auth/setup', 'POST', { token:d.token, email:d.email, password:d.password });
        notify('Compte principal créé. Connecte-toi avec tes identifiants.');
        renderUnauth(true);
      });
  } else {
    panel = form('Connexion', 'Accès par adresse e-mail et mot de passe.',
      [input('Adresse e-mail', 'email', 'email', 'admin@exemple.fr'),
       input('Mot de passe', 'password', 'password', 'Ton mot de passe')],
      'Se connecter', async d => {
        const result = await api('/api/auth/login', 'POST', { email:d.email, password:d.password });
        if (result.mfa_required) {
          renderMfaChallenge(result);
          return;
        }
        state.account = result.account;
        state.csrf = result.csrf;
        await showPanel();
      });
  }
  const footer = paragraph('Accès administrateur sécurisé par HTTPS · Aucun compte préconfiguré', 'auth-footer');
  wrap.append(brand, detail, panel, footer);
  app.appendChild(wrap);
}
function renderMfaChallenge(challenge) {
  app.replaceChildren();
  const shell = node('main', 'auth-layout');
  shell.append(node('div', 'auth-brand', '◈ CERATO NETWORK'));
  const box = node('section', 'form-panel');
  const isSetup = Boolean(challenge.mfa_setup);
  box.append(node('h1', '', isSetup ? 'Configurer le double facteur' : 'Vérification de sécurité'),
             paragraph(isSetup
               ? 'Compte privilégié : ajoute cette clé dans une application d’authentification. Aucun accès administrateur n’est accordé avant la validation.'
               : 'Saisis le code à 6 chiffres de ton application, ou un code de récupération personnel.'));
  if (isSetup) {
    const key = node('pre', 'secret-key', challenge.otp_secret || '');
    box.append(node('div', 'field-label', 'Clé TOTP à enregistrer'), key,
               paragraph('Tu peux aussi utiliser ce lien avec une application TOTP compatible :'));
    const uri = node('input', 'textinput');
    uri.value = challenge.otp_uri || '';
    uri.readOnly = true;
    uri.setAttribute('aria-label', 'Lien otpauth');
    box.append(uri);
  }
  const verifyForm = node('form', 'form');
  const otp = input('Code TOTP ou récupération', 'code', 'text',
                    isSetup ? '000000' : 'Code à 6 chiffres ou récupération');
  verifyForm.append(otp);
  const action = node('button', 'button primary', 'Vérifier et continuer');
  action.type = 'submit';
  verifyForm.append(action);
  verifyForm.addEventListener('submit', async event => {
    event.preventDefault();
    action.disabled = true;
    try {
      const code = otp.querySelector('input').value.trim();
      const result = await api('/api/auth/mfa/verify','POST',
                               {challenge:challenge.challenge,code});
      state.account = result.account;
      state.csrf = result.csrf;
      if (result.recovery_codes) {
        renderRecoveryCodes(result.recovery_codes);
      } else {
        await showPanel();
      }
    } catch(error) {
      notify(error.message,true);
    } finally {
      action.disabled = false;
    }
  });
  box.append(verifyForm,button('Retour à la connexion', () => renderUnauth(true), 'button small'));
  shell.append(box);
  app.append(shell);
}
function renderRecoveryCodes(codes) {
  app.replaceChildren();
  const shell = node('main', 'auth-layout');
  const panel = node('section','form-panel');
  panel.append(node('h1','','Sauvegarder tes codes de récupération'),
               paragraph('Ils sont affichés une seule fois. Stocke-les hors du serveur, dans un gestionnaire de mots de passe. Chaque code ne fonctionne qu’une fois.'));
  const pre = node('pre','secret-key',codes.join('\n'));
  const save = button('Copier les codes',async () => {
    try { await navigator.clipboard.writeText(codes.join('\n')); notify('Codes copiés. Conserve-les en lieu sûr.'); }
    catch (_) { notify('Copie non disponible : sélectionne manuellement les codes.',true); }
  });
  panel.append(pre,save,button('J’ai sauvegardé mes codes',async () => {
    await showPanel();
  },'button primary'));
  shell.append(node('div','auth-brand','◈ CERATO NETWORK'),panel);
  app.append(shell);
}
function menuButton(text, view) {
  const b = button(text, () => { state.view = view; renderPanel(); }, 'nav-item' + (state.view === view ? ' selected' : ''));
  return b;
}
function card(title, value, subtitle) {
  const section = node('div', 'metric-card');
  section.append(node('div', 'metric-label', title), node('div', 'metric-value', value), paragraph(subtitle));
  return section;
}
function section(title, subtitle) {
  const s = node('section', 'section');
  s.append(node('h2', '', title));
  if (subtitle) s.append(paragraph(subtitle));
  return s;
}
function valueOrUnknown(value) {
  return value === undefined || value === null || value === '' ? 'Indisponible' : String(value);
}
function dashboard(main) {
  const data = state.status || {};
  const peers = data.peers || {};
  const machines = data.machines || Object.entries(peers).map(([name, peer]) => ({ name, ...peer }));
  const grid = node('div', 'metric-grid');
  const liveCount = machines.filter(p => p.connected || (p.last_handshake && Date.now()/1000 - p.last_handshake < 180)).length;
  grid.append(card('État réseau', data.dashboard_mode === 'live' ? 'Données réelles' : 'Indisponible',
                   'Pas de données fictives'),
              card('Machines', machines.length, 'Enregistrées'),
              card('Handshake récent', liveCount, 'Dans les 3 dernières minutes'),
              card('Tunnel', data.tunnel_active ? 'Actif' : 'À vérifier', 'WireGuard'));
  main.appendChild(grid);
  const status = section('Passerelle', 'L’état est fourni par le moteur local, quand celui-ci est disponible.');
  if (state.account.role !== 'user') {
    const info = node('div', 'data-grid');
    info.append(card('Interface WAN', valueOrUnknown(data.wan_if), 'Interface du routeur'),
                card('IP WireGuard', valueOrUnknown(data.gateway_tunnel_ip), 'Réseau interne'),
                card('Port UDP', valueOrUnknown(data.wg_port), 'Écoute WireGuard'));
    status.appendChild(info);
  } else {
    status.append(paragraph('Les IP, clés et paramètres détaillés sont masqués pour les comptes en lecture seule.'));
  }
  main.appendChild(status);
  machinesView(main, machines);
}
function machinesView(main, supplied) {
  const list = supplied || ((state.status && state.status.machines) || Object.entries((state.status && state.status.peers) || {}).map(([name, peer]) => ({ name, ...peer })));
  const area = section('Machines & tunnels', 'États visibles uniquement lorsqu’ils sont remontés par le réseau.');
  const table = node('table', 'table');
  const header = node('tr');
  ['Machine', 'Connexion', 'Dernier contact', 'Agent'].forEach(x => header.appendChild(node('th', '', x)));
  table.appendChild(header);
  list.forEach(peer => {
    const row = node('tr');
    const h = Number(peer.last_handshake) || 0;
    const online = peer.connected || (h > 0 && Date.now()/1000 - h < 180);
    const seen = h ? new Date(h * 1000).toLocaleString('fr-FR') : 'Jamais';
    [peer.name || 'Inconnue', online ? 'Connectée' : 'Hors ligne',
     seen, peer.agent_version || 'Non remontée'].forEach(v => row.appendChild(node('td', '', v)));
    table.appendChild(row);
  });
  if (!list.length) {
    area.append(paragraph('Aucune machine disponible. Aucun statut inventé.'));
  } else {
    area.append(table);
  }
  main.append(area);
}
async function loadAccounts() {
  const result = await api('/api/accounts');
  state.accounts = result.accounts || [];
  renderPanel();
}
function accountsView(main) {
  const area = section('Comptes & permissions', 'Le propriétaire est protégé. Les co-administrateurs gèrent les autres comptes.');
  const table = node('table', 'table');
  const head = node('tr');
  ['E-mail', 'Rôle', 'État', 'Actions'].forEach(v => head.appendChild(node('th', '', v)));
  table.appendChild(head);
  state.accounts.forEach(acc => {
    const tr = node('tr');
    tr.append(node('td', '', acc.email), node('td', '', acc.role === 'owner' ? 'Propriétaire' : acc.role === 'admin' ? 'Administrateur' : 'Utilisateur'),
              node('td', '', acc.active ? 'Actif' : 'Désactivé'));
    const buttons = node('td');
    if (acc.role === 'owner') {
      buttons.appendChild(node('span', 'protected', 'Compte principal protégé'));
    } else if (acc.id !== state.account.id) {
      buttons.append(
        button(acc.active ? 'Désactiver' : 'Activer', async () => {
          try {
            await api('/api/accounts/' + acc.id, 'PATCH', {active: !acc.active});
            await loadAccounts();
          } catch(e) { notify(e.message,true); }
        }, 'button small'),
        button('Supprimer', async () => {
          if (!confirm('Supprimer le compte ' + acc.email + ' ?')) return;
          try {
            await api('/api/accounts/' + acc.id, 'DELETE', {});
            await loadAccounts();
          } catch(e) { notify(e.message,true); }
        }, 'button small danger')
      );
      if (acc.role === 'admin') {
        buttons.append(button('Réinitialiser 2FA',async()=>{
          if (!confirm('Réinitialiser le 2FA de ' + acc.email + ' ? Toutes ses sessions seront révoquées.')) return;
          try {
            await api('/api/accounts/' + acc.id,'PATCH',{reset_mfa:true});
            notify('2FA réinitialisé. Le compte devra réactiver sa double authentification.');
          } catch(e) { notify(e.message,true); }
        },'button small'));
      }
    } else buttons.append(node('span', '', 'Compte courant'));
    tr.append(buttons);
    table.appendChild(tr);
  });
  area.append(table);
  const create = form('Ajouter un compte', 'Tu peux créer un administrateur ou un utilisateur en lecture seule.',
    [input('Adresse e-mail', 'email', 'email', 'utilisateur@exemple.fr'),
     select('Rôle', 'role', [['user','Utilisateur — lecture seule'],['admin','Administrateur']]),
     input('Mot de passe initial', 'password', 'password', '14 caractères minimum')],
    'Créer le compte', async d => {
      await api('/api/accounts', 'POST', d);
      notify('Compte créé. Le mot de passe initial doit être transmis hors du panneau.');
      await loadAccounts();
    });
  main.append(area, create);
}
function profileView(main) {
  main.append(form('Mes identifiants', 'Tu peux modifier ton propre compte. Toutes tes sessions seront révoquées.',
    [input('Mot de passe actuel', 'current_password', 'password', 'Obligatoire'),
     input('Nouvelle adresse e-mail (facultatif)', 'email', 'email', 'Laisser vide pour conserver', false),
     input('Nouveau mot de passe (facultatif)', 'new_password', 'password', 'Laisser vide pour conserver', false)],
    'Enregistrer et me déconnecter', async d => {
      const body = { current_password:d.current_password };
      if (d.email) body.email = d.email;
      if (d.new_password) body.new_password = d.new_password;
      await api('/api/auth/me','PATCH',body);
      notify('Identifiants modifiés. Reconnexion nécessaire.');
      state.account = null;
      state.csrf = '';
      renderUnauth(true);
    }));
}
function updatesView(main) {
  const area = section('Centre de mises à jour', 'Vérification cryptographique des releases locales. L’installation reste désactivée pendant le développement.');
  const data = state.updateInfo;
  const grid = node('div','data-grid');
  grid.append(card('Version installée', data?.installed_version || 'Non suivie','État du panneau'),
              card('Canal', data?.channel || 'Stable','Stable / Bêta'),
              card('Release disponible',data?.available_version || 'Indisponible','Archive du VPS de build'));
  area.append(grid);
  const indicator = node('div','update-verify', data?.verified
      ? '✓ Signature Ed25519 et SHA-256 vérifiés'
      : data?.reason || 'Aucune release vérifiée chargée');
  if (data?.verified) indicator.classList.add('verified');
  area.append(indicator);
  if (data?.reason) area.append(paragraph(data.reason));
  area.append(button('Vérifier les mises à jour', async () => {
    try {
      state.updateInfo = await api('/api/updates/check','POST',{});
      renderPanel();
      notify(state.updateInfo.verified ? 'Release signée vérifiée.' : 'Aucune mise à jour installable pour le moment.');
    } catch(e) { notify(e.message,true); }
  }, 'button primary'));
  const blocked = button('Installer sur le panneau et les machines', () => {}, 'button');
  blocked.disabled = true;
  blocked.title = 'Activation après tests de sauvegarde, rollback et déploiement des agents';
  area.append(blocked);
  area.append(paragraph('La publication est réalisée sur le VPS de build. Aucune installation ni action distante n’est possible dans ce mode de développement.'));
  main.appendChild(area);
}
function renderPanel() {
  app.replaceChildren();
  const frame = node('div','layout');
  const sidebar = node('aside','sidebar');
  sidebar.append(node('div','logo','◈  CERATO NETWORK'), node('div','nav-label','INFRASTRUCTURE'),
    menuButton('Vue d’ensemble','dashboard'), menuButton('Machines & tunnels','machines'),
    menuButton('Mises à jour','updates'));
  if (state.account.role !== 'user') sidebar.append(node('div','nav-label','ADMINISTRATION'),menuButton('Comptes','accounts'));
  sidebar.append(node('div','nav-label','PERSONNEL'),menuButton('Mes identifiants','profile'));
  const content = node('div','content');
  const top = node('header','topbar');
  const identity = node('div','identity');
  identity.append(node('strong','',state.account.email),
                  node('span','role', state.account.role === 'owner' ? 'Propriétaire principal' :
                       state.account.role === 'admin' ? 'Administrateur' : 'Lecture seule'));
  top.append(identity,button('Déconnexion',async()=>{
    try{ await api('/api/auth/logout','POST',{}); }catch(_) {}
    state.account=null;state.csrf='';
    renderUnauth(true);
  },'button small'));
  const main = node('main','main');
  main.append(node('h1','page-title', {
    dashboard:'Vue d’ensemble',machines:'Machines & tunnels',updates:'Mises à jour',
    accounts:'Comptes & permissions',profile:'Mes identifiants'}[state.view] || 'Cerato Network'));
  if(state.view === 'dashboard') dashboard(main);
  if(state.view === 'machines') machinesView(main);
  if(state.view === 'updates') updatesView(main);
  if(state.view === 'accounts' && state.account.role !== 'user') accountsView(main);
  if(state.view === 'profile') profileView(main);
  main.append(paragraph('Cerato Network — version de développement · Les modifications réseau sont désactivées.', 'disclaimer'));
  content.append(top,main);
  frame.append(sidebar,content);
  app.appendChild(frame);
}
async function showPanel() {
  try {
    state.status = await api('/api/status');
  } catch (e) { state.status={dashboard_mode:'unavailable',peers:{}}; notify(e.message, true); }
  renderPanel();
}
(async function initialize() {
  try {
    const me = await api('/api/auth/me');
    state.account = me.account;
    state.csrf = me.csrf;
    await showPanel();
  } catch (_) {
    try {
      const info = await api('/api/auth/setup-status');
      renderUnauth(info.initialized);
    } catch(e) { app.replaceChildren(paragraph('Erreur de connexion à la console : ' + e.message)); }
  }
})();

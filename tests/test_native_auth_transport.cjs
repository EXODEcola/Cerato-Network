/* Test scoped CSRF transport from the EXACT native-auth overlay source. */
'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const assert=require('node:assert/strict');

const source=fs.readFileSync(path.resolve(__dirname,'../web/live-auth-overlay.js'),'utf8');
const start=source.indexOf('  let transportInstalled=false;');
const end=source.indexOf('  function overlay(heading,subtitle) {',start);
assert.ok(start>0&&end>start,'Scoped native CSRF transport missing');
const snippet=source.slice(start,end);
const calls=[];
const origin='https://panel.example.net';
const window={
  location:{origin,href:origin+'/index.html'},
  fetch:async function(...args){calls.push(args);return {ok:true,status:200};},
};
const state={account:{role:'owner'},csrf:'secret-csrf-for-test'};
const ctx=vm.createContext({state,window,Headers,URL});
vm.runInContext(snippet+'\ninstallNativeTransport();installNativeTransport();',ctx);
(async()=>{
  await window.fetch('/api/nat/add',{method:'POST',headers:{'Content-Type':'application/json'}});
  assert.equal(calls.length,1);
  assert.equal(calls[0][1].headers.get('X-Cerato-CSRF'),state.csrf);
  assert.equal(calls[0][1].credentials,'same-origin');

  await window.fetch('/api/status',{method:'GET'});
  assert.equal(calls[1][1].headers,undefined);

  await window.fetch('https://attacker.example.net/api/ip/configure',{method:'POST'});
  assert.equal(calls[2][1].headers,undefined);
  assert.equal(calls[2][1].credentials,undefined);

  await window.fetch('/api/ip/configure',{
    method:'POST',headers:{'X-Cerato-CSRF':'existing-approved-token'}
  });
  assert.equal(calls[3][1].headers.get('X-Cerato-CSRF'),'existing-approved-token');

  const readRequest={url:origin+'/api/accounts/2',method:'PATCH',headers:{
    'Content-Type':'application/json'
  }};
  await window.fetch(readRequest,{});
  assert.equal(calls[4][1].headers.get('X-Cerato-CSRF'),state.csrf);
  assert.equal(calls.length,5);

  const userWindow={
    location:{origin,href:origin+'/'},
    fetch:async function(...args){return args;}
  };
  const userCtx=vm.createContext({state:{account:null,csrf:''},window:userWindow,Headers,URL});
  vm.runInContext(snippet+'\ninstallNativeTransport();',userCtx);
  const result=await userWindow.fetch('/api/nat/add',{method:'POST'});
  assert.equal(result[1].headers,undefined);

  for(const required of ('function myAccount()','reset_mfa:true',
                         'acc.mfa_enabled','acc.active_sessions',
                         'endpoint+\'mfa/verify\'')){
    assert.ok(source.includes(required),'Missing native account control '+required);
  }
  assert.ok(!source.includes('localStorage'));
  console.log('PASS: CSRF scoped to same-origin writes; account and MFA controls');
})().catch(e=>{console.error(e);process.exitCode=1;});

/* Real-source DOM smoke tests, no browser dependency or network access. */
'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

const SCRIPT=fs.readFileSync(path.resolve(__dirname,'../web/app.js'),'utf8');
const PUBLIC='54.37.165.151';
const ROUTES={
  schema:'cerato-ipv4-allocations-v1',total:1,allocated_count:1,
  available_count:0,routed_count:1,warnings:0,nat_publications:0,
  entries:[{ip:PUBLIC,peer:'dell-r530',mode:'routed-wg',
            state:'routed',assigned:true}]
};

class Element{
  constructor(tag){
    this.tagName=tag.toUpperCase();this.children=[];this.attributes={};
    this.className='';this.textContent='';this.events={};
    this.classList={add:()=>{},remove:()=>{}};
  }
  append(...children){for(const child of children)this.appendChild(child);}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(...children){this.children=children;}
  setAttribute(key,value){this.attributes[key]=value;}
  addEventListener(event,fn){this.events[event]=fn;}
  querySelector(tag){
    return this.children.find(ch=>ch.tagName===tag.toUpperCase())||null;
  }
}
function textTree(el){
  return [el.textContent,...el.children.flatMap(textTree)].join(' ');
}
function elements(el){
  return [el,...el.children.flatMap(elements)];
}
function makeApp(role,initialHash){
  const root=new Element('div'),events={},calls=[];
  const location={hash:initialHash};
  const window={location,
    addEventListener:(name,fn)=>{events[name]=fn;}};
  const document={
    getElementById:(name)=>name==='app'?root:null,
    createElement:(tag)=>new Element(tag),
    body:new Element('body')
  };
  const history={
    pushState(_state,_unused,newHash){location.hash=newHash;}
  };
  const api=async(url)=>{
    calls.push(url);
    const object={
      '/api/auth/me':{account:{id:1,email:'owner@example.test',role},
                      csrf:'fake-csrf-for-test-only'},
      '/api/status':{dashboard_mode:'live',tunnel_active:true,
                     peers:{'dell-r530':{last_handshake:0}},
                     wg_port:51820},
      '/api/ip/allocations':ROUTES,
      '/api/accounts':{accounts:[]},
      '/api/updates':{channel:'beta',configured:true,installable:false},
    };
    if(!(url in object))throw Error('Unexpected API '+url);
    return {ok:true,status:200,json:async()=>object[url]};
  };
  const context=vm.createContext({
    window,document,history,fetch:api,Date,console,URL,
    setTimeout,clearTimeout,FormData:function(){},
  });
  vm.runInContext(SCRIPT,context,{filename:'web/app.js'});
  return {
    root,window,events,calls,context,
    view:()=>vm.runInContext('state.view',context),
    text:()=>textTree(root),
    navButton:(name)=>elements(root).find(
      el=>el.tagName==='BUTTON'&&el.textContent===name),
  };
}
async function flush(){
  for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));
}
(async()=>{
  const owner=makeApp('owner','#/routes');
  await flush();
  assert.equal(owner.view(),'routes','F5 should restore routed IPv4 page');
  assert.match(owner.text(),/Routage IPv4/);
  assert.match(owner.text(),/dell-r530/);
  assert.match(owner.text(),/Routage complet \/32/);
  assert.match(owner.text(),/54\.37\.165\.151/);
  assert.deepEqual(owner.calls,
    ['/api/auth/me','/api/ip/allocations']);
  const nav=owner.navButton('Machines & tunnels');
  assert.ok(nav,'navigation button missing');
  await nav.events.click();
  await flush();
  assert.equal(owner.window.location.hash,'#/machines');
  assert.equal(owner.view(),'machines');
  const reload=makeApp('owner',owner.window.location.hash);
  await flush();
  assert.equal(reload.view(),'machines','view lost on new browser load');

  const viewer=makeApp('user','#/routes');
  await flush();
  assert.equal(viewer.view(),'dashboard',
    'viewer must never land on privileged route view');
  assert.ok(!viewer.calls.includes('/api/ip/allocations'),
    'viewer attempted to fetch sensitive IPv4 data');
  assert.doesNotMatch(viewer.text(),/54\.37\.165\.151/);
  assert.ok(!viewer.navButton('Routage IPv4'),
    'viewer navigation exposes privileged routes');
  console.log('PASS: routed IPv4 view, URL F5/back state and viewer isolation');
})().catch(e=>{console.error(e);process.exitCode=1;});

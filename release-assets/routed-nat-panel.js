/* CERATO-NETWORK-ROUTED-NAT-UI-V1 */
// Display routed public IPv4s alongside NAT publications, without inventing
// a DNAT rule or granting a network mutation action.
function ceratoRenderDirectRoutedIPv4(base,data){
  const old=document.getElementById('cerato-direct-routed-ipv4');
  if(old)old.remove();
  if(!data||!Array.isArray(data.entries))return;
  const routes=data.entries.filter(row=>row&&row.mode==='routed-wg');
  if(!routes.length)return;
  const panel=document.createElement('section');
  panel.id='cerato-direct-routed-ipv4';
  panel.setAttribute('aria-label','Routages IPv4 publics');
  panel.style.cssText='border:1px solid #344049;border-radius:8px;'+
    'background:#1d2327;margin:16px 0;padding:16px;color:#d8e4e7;';
  const h=document.createElement('h3');
  h.textContent='Routages IPv4 directs ('+routes.length+')';
  h.style.cssText='font-size:15px;font-weight:650;margin:0 0 6px;';
  const description=document.createElement('p');
  description.textContent='IPv4 publiques entièrement acheminées par WireGuard. '+
    'Ces attributions fonctionnent sans publication NAT par port ; '+
    'le filtrage des ports se règle sur la machine destinataire.';
  description.style.cssText='font-size:12px;color:#9bb0b7;margin:0 0 12px;';
  const table=document.createElement('table');
  table.style.cssText='border-collapse:collapse;width:100%;font-size:12px;';
  const head=document.createElement('thead');
  const labels=['IPv4 publique','Machine','Mode','État'];
  const headers=document.createElement('tr');
  for(const label of labels){
    const th=document.createElement('th');
    th.scope='col';
    th.textContent=label;
    th.style.cssText='text-align:left;padding:10px;'+
      'background:#252d32;border-bottom:1px solid #36444a;color:#b9cbd0;';
    headers.append(th);
  }
  head.append(headers);
  const body=document.createElement('tbody');
  for(const route of routes){
    const tr=document.createElement('tr');
    const values=[
      String(route.ip||'—'),
      String(route.peer||'Machine inconnue'),
      'Routage complet /32 · WireGuard',
      route.state==='warning'?'Conflit à vérifier':'Attribuée',
    ];
    for(const value of values){
      const td=document.createElement('td');
      td.textContent=value;
      td.style.cssText='padding:10px;border-bottom:1px solid #303a40;';
      tr.append(td);
    }
    body.append(tr);
  }
  table.append(head,body);
  panel.append(h,description,table);
  base.append(panel);
}

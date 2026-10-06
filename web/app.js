'use strict';
const $ = id => document.getElementById(id);
const severityNames = {critical:'Kritik',high:'Yüksek',medium:'Orta',low:'Düşük',info:'Bilgi'};
const stateNames = {tested:'Test edildi',skipped:'Atlandı',inconclusive:'Sonuçsuz',not_implemented:'Uygulanmadı'};
const jobNames = {queued:'Hazırlanıyor',running:'Çalışıyor',complete:'Rapor hazır',partial:'Kısmi rapor',stopped:'Durduruldu',failed:'Tamamlanamadı',interrupted:'Yarıda kaldı'};
let state = {key:'',site:null,launching:false,job:null,filter:'all',tab:'findings',scans:[],poll:null};

function el(tag, attrs={}, ...children) {
  const node = document.createElement(tag);
  for (const [name,value] of Object.entries(attrs)) {
    if (name==='class') node.className = value;
    else if (name==='onClick') node.addEventListener('click', value);
    else node.setAttribute(name,String(value));
  }
  for (const child of children.flat()) if (child!==null && child!==undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
function show(id, value=true) { $(id).classList.toggle('hidden',!value); }
function notice(text, success=false) {
  $('notice').textContent=text;
  $('notice').classList.toggle('success',success);
  show('notice');
}
async function api(path, data) {
  const options={headers:{'Content-Type':'application/json','X-Kanit-Key':state.key},credentials:'same-origin'};
  if (data!==undefined) { options.method='POST'; options.body=JSON.stringify(data); }
  const response=await fetch(path,options);
  const result=await response.json();
  if (!response.ok) throw new Error(result.error || 'İşlem tamamlanamadı.');
  return result;
}
function scanBusy() {
  return state.launching || Boolean(state.job && ['queued','running','stopping'].includes(state.job.status));
}
function syncScanControls() {
  const busy=scanBusy();
  for(const id of ['scan-button','site-url','lab-vulnerable','lab-fixed']) $(id).disabled=busy;
  $('site-form').querySelector('button').disabled=busy;
  document.querySelectorAll('#history button').forEach(button=>button.disabled=busy);
}
async function launchAction(button, work) {
  if(scanBusy()) return;
  state.launching=true;
  syncScanControls();
  try { await action(button,work); }
  finally { state.launching=false; syncScanControls(); }
}
async function action(button, work) {
  button.disabled=true;
  show('notice',false);
  try { await work(); } catch(error) { notice(error.message); }
  finally { button.disabled=false; syncScanControls(); }
}
function flow(step) {
  document.querySelectorAll('#flow li').forEach(item=>{
    const n=Number(item.dataset.step);
    item.classList.toggle('active', n===step);
    item.classList.toggle('done',n<step);
    if (n===step) item.setAttribute('aria-current','step'); else item.removeAttribute('aria-current');
  });
}
function cleanAccounts() {
  ['a-session','b-session'].forEach(id=>$(id).value='');
}
function resetFields() {
  ['a-session','b-session','a-url','b-url','a-marker','b-marker','auth-url','auth-marker','identity-url','identity-field','sql-url','sql-parameter','sql-private-value','sql-private-marker'].forEach(id=>$(id).value='');
  $('sensitive').checked=false;
  $('read-only').checked=false;
  $('a-type').value='cookie'; $('b-type').value='cookie';
}
function setSite(site) {
  state.site=site;
  resetFields();
  $('site-url').value=site.origin;
  $('scope-status').textContent='Tarama kapsamı hazır';
  $('scope-status').className='badge blue';
  show('scan-setup');
  flow(1);
}
function fillLab(config) {
  for (const name of ['a','b']) {
    $(name+'-session').value=config.accounts[name].cookie;
    $(name+'-url').value=config.authorization[name+'_url'];
    $(name+'-marker').value=config.authorization[name+'_marker'];
  }
  $('identity-url').value=config.identity.url;
  $('identity-field').value=config.identity.field;
  $('auth-url').value=config.authentication.url;
  $('auth-marker').value=config.authentication.marker;
  const injection=config.injection[0];
  $('sql-url').value=injection.url;
  $('sql-parameter').value=injection.parameter;
  $('sql-private-marker').value=injection.restricted_marker;
  $('sql-private-value').value=injection.restricted_value;
  $('sensitive').checked=true;
  $('read-only').checked=true;
}
function readConfig() {
  const value=id=>$(id).value.trim();
  const config={accounts:{}};
  for (const who of ['a','b']) if (value(who+'-session')) config.accounts[who] = {[$(who+'-type').value]:value(who+'-session')};
  const impact=$('sensitive').checked?'sensitive':'unknown';
  if(value('identity-url')) config.identity={url:value('identity-url'),field:value('identity-field')||'id'};
  if (value('a-url')||value('b-url')) config.authorization={a_url:value('a-url'),b_url:value('b-url'),a_marker:value('a-marker'),b_marker:value('b-marker'),impact};
  if (value('auth-url')||value('auth-marker')) config.authentication={url:value('auth-url'),marker:value('auth-marker'),impact};
  if (value('sql-url')) config.injection=[{url:value('sql-url'),parameter:value('sql-parameter'),restricted_marker:value('sql-private-marker'),restricted_value:value('sql-private-value'),impact}];
  return config;
}
function history() {
  const host=job=>{try{return new URL(job.origin).host;}catch{return 'İnceleme';}};
  $('history').replaceChildren(...state.scans.slice(0,6).map(job=>el('button',{class:'history-item',type:'button',onClick:()=>action($('pdf'),async()=>{
    if(scanBusy()) return;
    const current=await api('/api/scans/'+job.id);
    if(scanBusy()) return;
    setJob(current);
    if (['running','queued'].includes(current.status)) beginPolling();
  })},host(job),el('small',{},jobNames[job.status]||job.status,' · ',new Date(job.created_at*1000).toLocaleDateString('tr-TR',{day:'numeric',month:'short'})))));
  if (!state.scans.length) $('history').append(el('p',{class:'muted small'},'Henüz bir inceleme yok.'));
}
function setJob(job) {
  state.job=job;
  const active=['queued','running','stopping'].includes(job.status);
  show('scan-progress',active);
  $('progress-detail').textContent=job.stage;
  $('progress-bar').value=job.percent;
  $('request-count').textContent=job.requests+' / 240 istek · '+Math.round(job.percent)+'% aşama ilerlemesi';
  $('result-status').textContent=jobNames[job.status]||job.status;
  $('result-status').className='badge '+(job.status==='complete'?'green':'neutral');
  $('result-subtitle').textContent=job.origin+' · '+new Date(job.created_at*1000).toLocaleString('tr-TR',{dateStyle:'short',timeStyle:'short'});
  flow(active?2:3);
  const existing=state.scans.findIndex(s=>s.id===job.id);
  const summary={...job}; delete summary.report;
  if(existing>=0) state.scans[existing]=summary; else state.scans.unshift(summary);
  history();
  syncScanControls();
  if(job.report) {
    show('empty',false); show('report-view');
    show('pdf'); $('pdf').href='/api/scans/'+job.id+'/pdf';
    $('pdf').setAttribute('download','safeZ-'+job.id+'.pdf');
    renderReport();
  } else {
    show('empty'); show('report-view',false); show('pdf',false);
    for (const id of ['critical-count','high-count','medium-count','suspected-count']) { $(id).textContent='—'; $(id).classList.remove('has-risk'); }
  }
  if(!active) {
    cleanAccounts();
    $('stop-button').disabled=false; $('stop-button').textContent='Durdur';
    if (state.poll) clearTimeout(state.poll);
    state.poll=null;
    if(job.error) notice(job.error);
  }
}
function beginPolling() {
  if(state.poll) clearTimeout(state.poll);
  async function poll() {
    try {
      const job=await api('/api/scans/'+state.job.id);
      setJob(job);
      if(['queued','running','stopping'].includes(job.status)) state.poll=setTimeout(poll,700);
    } catch(error) { notice('Tarama durumu alınamadı: '+error.message); state.poll=setTimeout(poll,1800); }
  }
  state.poll=setTimeout(poll,400);
}
function table(headers,rows,cls='discovery-table') {
  return el('div',{class:'table-wrap'},el('table',{class:cls},el('thead',{},el('tr',{},...headers.map(x=>el('th',{scope:'col'},x)))),el('tbody',{},...rows.map(row=>el('tr',{},...row.map(cell=>el('td',{},cell)))))));
}
function findingCard(f) {
  const suspected=f.status==='suspected';
  const card=el('article',{class:'finding '+f.severity+(suspected?' suspected':'')});
  card.append(el('div',{class:'finding-header'},el('h3',{},f.title),el('div',{class:'finding-badges'},el('span',{class:'badge '+f.severity},severityNames[f.severity]||f.severity),el('span',{class:'status-text'+(suspected?' suspected':'')},suspected?'Şüpheli':'Doğrulanmış'))));
  const where=f.location||{};
  card.append(el('p',{class:'finding-location'},el('code',{},(where.method||'GET')+' '+(where.endpoint||f.url)),f.parameter?' · Parametre: '+f.parameter:'',where.response_line?' · Yanıt satırı: '+where.response_line:''));
  if(f.condition) {
    card.append(el('div',{class:'finding-summary'},el('div',{},el('h4',{},'Sorun nedir?'),el('p',{},f.condition)),el('div',{},el('h4',{},'Ne olabilir?'),el('p',{},f.impact))));
  } else if(f.note) card.append(el('p',{class:'muted small'},f.note));
  card.append(el('div',{class:'remedy'},el('h4',{},'Nasıl düzeltilir?'),el('p',{},f.fix||'Motor bu uyarı için çözüm belirtmedi. Elle inceleyin.')));
  if(f.english) {
    const english=el('div',{class:'evidence-content'},el('h4',{},f.english.title),el('p',{},'What was observed? '+f.english.condition),el('p',{},'Impact: '+f.english.impact),el('p',{},'Remediation: '+f.english.fix),el('h4',{},'Safe reproduction'),el('ol',{},...(f.english.steps||[]).map(step=>el('li',{},step))));
    card.append(el('details',{lang:'en',class:'english-explanation'},el('summary',{},'English explanation'),english));
  }
  if(Array.isArray(f.evidence)) {
    const evidence=el('div',{class:'evidence-content'},el('p',{},'Etkilenen adres: ',el('code',{},f.url)),el('p',{},'Parametre: ',f.parameter||'Yok',' · ',f.repeats,' karşılaştırma turu'),el('p',{},'Keşif kaynağı: '+(where.discovery_source||'Test adresi')),where.fields?el('p',{},'Alanlar: '+where.fields.join(', ')):null,el('h4',{},'Güvenli tekrar üretme'),el('ol',{},...(f.steps||[]).map(step=>el('li',{},step))));
    evidence.append(table(['Kontrol / istek','HTTP','İşaretleyici','Yanıt özeti'],f.evidence.map(e=>[el('div',{},e.test,e.request?el('p',{},el('code',{},(e.method||'GET')+' '+e.request)):null),e.http_status,'marker_present' in e?(e.marker_present?'Var':'Yok'):'—',el('code',{title:e.sha256},e.sha256.slice(0,16))]),'evidence-table'),el('p',{class:'field-note'},'Oturum ve yanıt gövdeleri saklanmaz. İşaretleyici değerleri maskelenir; yanıtlar SHA-256 özetiyle bağlanır. Sunucu kaynak kodunun satırı HTTP taramasından belirlenemez; bildirilen satır varsa HTTP yanıtına aittir.'));
    card.append(el('details',{},el('summary',{},'Teknik kanıt ve tekrar üretme adımları'),evidence));
  }
  return card;
}
function renderFindings() {
  const report=state.job.report;
  let rows=state.filter==='suspected'?[...report.findings.filter(f=>f.status==='suspected'),...(report.passive_alerts||[])]:report.findings;
  if(state.filter==='high') rows=rows.filter(f=>f.status==='confirmed'&&['high','critical'].includes(f.severity));
  if(state.filter==='medium') rows=rows.filter(f=>f.status==='confirmed'&&f.severity==='medium');
  if(state.filter==='all') rows=[...rows,...(report.passive_alerts||[]).filter(f=>f.severity==='high')];
  $('findings').replaceChildren(...rows.map(findingCard));
  if(!rows.length) $('findings').append(el('div',{class:'empty-state'},el('h3',{},state.filter==='suspected'?'Şüpheli motor uyarısı yok.':'Bu görünümde doğrulanmış bulgu yok.'),el('p',{},'Test kapsamını ve tamamlanamayan kontrolleri inceleyin.')));
  $('relationships').replaceChildren(...(report.relationships||[]).map(x=>el('p',{class:'relationship-note'},x)));
}
function renderReport() {
  const report=state.job.report;
  for (const type of ['critical','high','medium']) {
    const n=report.findings.filter(f=>f.status==='confirmed'&&f.severity===type).length;
    $(type+'-count').textContent=n;
    $(type+'-count').classList.toggle('has-risk',n>0&&['high','critical'].includes(type));
  }
  $('suspected-count').textContent=(report.passive_alerts||[]).length+report.findings.filter(f=>f.status==='suspected').length;
  const warnings=[...(report.warnings||[])];
  if(state.job.status!=='complete') warnings.unshift('Bu rapor kısmi incelemeye aittir. Tarama tamamlanmadı.');
  if(report.engine.state==='unavailable') warnings.push(report.engine.detail);
  $('warnings').replaceChildren(...warnings.map(x=>el('p',{},x)));
  const tested=report.coverage.filter(c=>c.state==='tested').length;
  const missing=report.coverage.filter(c=>['skipped','inconclusive'].includes(c.state)).length;
  const unsupported=report.coverage.filter(c=>c.state==='not_implemented').length;
  $('coverage').replaceChildren(el('p',{class:'coverage-summary'},tested+' kontrol çalıştı · '+missing+' kontrol için uygun girdi/koşul eksik · '+unsupported+' ek senaryo uygulanmadı'),...report.coverage.map(c=>el('div',{class:'coverage-row'},el('div',{},el('h3',{},c.name),el('p',{},c.detail),el('p',{class:'coverage-requests'},c.requests+' GET isteği'),c.detail_en?el('details',{lang:'en'},el('summary',{},'English'),el('p',{},(c.name_en||c.kind)+': '+c.detail_en)):null),el('span',{class:'badge '+(c.state==='tested'?'blue':'neutral')},stateNames[c.state]||c.state))));
  $('engine-note').textContent='OWASP ZAP: '+report.engine.detail;
  const discovery=report.discovery||{pages:[],forms:[],parameters:[],skipped:[]};
  $('discovery').replaceChildren(table(['Adres','HTTP','Yanıt türü'],discovery.pages.map(page=>[el('code',{},page.url),page.status,page.type.split(';')[0]+' · '+(page.source||'HTML')])));
  $('discovery').append(el('div',{class:'discovery-section'},el('h3',{},'Formlar'),...discovery.forms.map(f=>el('p',{},f.method+' · '+f.url+' · Alanlar: '+f.fields.map(x=>x.name).join(', ')+' · '+(f.tested?'GET isteği gönderildi':'Gönderilmedi')))));
  if(!discovery.forms.length) $('discovery').lastChild.append(el('p',{},'Form keşfedilmedi.'));
  $('discovery').append(el('div',{class:'discovery-section'},el('h3',{},'Parametreler'),...discovery.parameters.map(p=>el('p',{},p.name+' · '+p.url+' · '+(p.source||'Keşfedilen parametre')))));
  if(discovery.skipped.length) $('discovery').append(el('div',{class:'discovery-section'},el('h3',{},'Atlanan adresler'),...discovery.skipped.map(p=>el('p',{},p.url+' · '+p.reason))));
  renderFindings();
}
function selectTab(tab) {
  state.tab=tab;
  for(const name of ['findings','coverage','discovery']) {
    show(name+'-view',name===tab);
    $('tab-'+name).classList.toggle('selected',name===tab);
    $('tab-'+name).setAttribute('aria-selected',String(name===tab));
  }
}

async function launchScan(config={}) {
  if(!state.site) throw new Error('Önce domain veya site adresini girin.');
  const job=await api('/api/scans',{site_id:state.site.id,config,read_only:true});
  cleanAccounts();
  setJob(job); beginPolling();
  $('scan-progress').scrollIntoView({block:'nearest',behavior:'smooth'});
}
$('site-form').addEventListener('submit',event=>{
  event.preventDefault();
  launchAction(event.submitter || $('site-form').querySelector('button'),async()=>{
    setSite(await api('/api/sites',{url:$('site-url').value.trim()}));
    await launchScan();
  });
});
for(const mode of ['vulnerable','fixed']) $('lab-'+mode).addEventListener('click',()=>launchAction($('lab-'+mode),async()=>{
  const result=await api('/api/lab',{mode});
  setSite(result.site); fillLab(result.config);
  await launchScan(result.config);
}));
$('scan-button').addEventListener('click',()=>launchAction($('scan-button'),async()=>{
  if(!$('read-only').checked) throw new Error('Salt okunur test uçları ve kendi test kayıtlarınızla çalıştığınızı belirtin.');
  await launchScan(readConfig());
}));
$('stop-button').addEventListener('click',()=>action($('stop-button'),async()=>{
  await api('/api/scans/'+state.job.id+'/stop',{});
  $('stop-button').textContent='Durduruluyor…';
  $('progress-detail').textContent='Yeni istekler engellendi; devam eden bağlantı kapatılıyor.';
}));
for(const tab of ['findings','coverage','discovery']) $('tab-'+tab).addEventListener('click',()=>selectTab(tab));
document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{
  state.filter=button.dataset.filter;
  document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('selected',x===button));
  renderFindings();
}));
async function boot() {
  try {
    const result=await api('/api/bootstrap');
    state.key=result.key; state.scans=result.scans; history();
    $('rate').textContent=result.rate;
    $('engine-status').textContent=result.engine.detail;
    if(result.sites.length) setSite(result.sites[0]);
    if(result.scans.length) {
      const active=result.scans.find(s=>['queued','running','stopping'].includes(s.status));
      setJob(await api('/api/scans/'+(active||result.scans[0]).id));
      if(active) beginPolling();
    }
  } catch(error) { notice('Uygulama yüklenemedi: '+error.message+' Sayfayı yenileyin.'); }
}
boot();

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const sourcePath = process.env.SAFEZ_APP_JS || require('node:path').join(__dirname, '..', 'web', 'app.js');
const source = fs.readFileSync(sourcePath, 'utf8').replace(/boot\(\);\s*$/, '');
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(resolve => setImmediate(resolve)); };
const job = (id, status) => ({id, status, site_id:id, origin:'https://' + id + '.test', created_at:1, stage:status, percent:status === 'complete' ? 100 : 10, requests:1, report:null});

function harness(respond) {
  class Element {
    constructor(id = '', tagName = 'DIV') {
      this.id = id; this.tagName = tagName; this.value = ''; this.disabled = false; this.checked = false;
      this.children = []; this.listeners = {}; this.dataset = {}; this.classes = new Set();
      this.classList = {toggle:(name, value) => value ? this.classes.add(name) : this.classes.delete(name), remove:name => this.classes.delete(name)};
    }
    setAttribute(name, value) { this[name] = value; }
    removeAttribute(name) { delete this[name]; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    querySelectorAll(selector) {
      if (this.id === 'site-form' && selector === 'button') return [get('submit')];
      if (selector === 'button') return this.children.filter(child => child.tagName === 'BUTTON');
      return [];
    }
    closest(selector) { return this.id === 'submit' && selector === '#site-form' ? get('site-form') : null; }
    scrollIntoView() {}
    // Invoke the real handler even if disabled, so the regression also checks its guard.
    dispatch(type, event = {}) { return this.listeners[type]?.({preventDefault() {}, ...event}); }
  }
  const nodes = new Map();
  const get = id => { if (!nodes.has(id)) nodes.set(id, new Element(id, id === 'submit' || id.startsWith('lab-') ? 'BUTTON' : 'DIV')); return nodes.get(id); };
  const requests = []; const timers = new Map(); let timer = 0;
  const context = vm.createContext({
    Node:Element, URL, console,
    document:{getElementById:get, createElement:tag => new Element('', tag.toUpperCase()), createTextNode:String,
      querySelectorAll:selector => selector === '#history button' ? get('history').querySelectorAll('button') : []},
    setTimeout:callback => { timers.set(++timer, callback); return timer; }, clearTimeout:id => timers.delete(id),
    fetch:async (path, options) => {
      requests.push({path, data:options.body ? JSON.parse(options.body) : undefined});
      const result = await respond(path, options);
      return {ok:true, json:async () => result};
    }
  });
  vm.runInContext(source, context, {filename:sourcePath});
  return {get, requests, timers, run:code => vm.runInContext(code, context)};
}

test('viewing history cannot replace an active job or stop its polling', async () => {
  const past = job('past', 'complete');
  const h = harness(async path => { assert.equal(path, '/api/scans/past'); return past; });
  h.run(`state.scans = [${JSON.stringify(past)}]; setJob(${JSON.stringify(job('active', 'running'))}); beginPolling();`);
  const poll = h.run('state.poll');
  const pastButton = h.get('history').children[1];
  assert.ok(pastButton, 'The real history renderer must create the completed report button');
  pastButton.dispatch('click');
  await settle();
  assert.equal(h.run('state.job.id'), 'active', 'History must not overwrite the active scan');
  assert.equal(h.run('state.poll'), poll, 'History must preserve the active poll');
  assert.ok(h.timers.has(poll), 'Active polling timer must remain scheduled');
  assert.equal(h.get('scan-button').disabled, true, 'Scan controls must remain disabled');
});

test('a pending domain registration prevents a second launch', async () => {
  let resolveRegistration;
  const registration = new Promise(resolve => { resolveRegistration = resolve; });
  const h = harness(async path => {
    if (path === '/api/sites') return registration;
    if (path === '/api/scans') return job('first', 'running');
    if (path === '/api/lab') return new Promise(() => {});
    throw new Error('Unexpected request: ' + path);
  });
  h.get('site-url').value = 'first.test';
  h.get('site-form').dispatch('submit', {submitter:h.get('submit')});
  await settle();
  assert.equal(h.requests.filter(request => request.path === '/api/sites').length, 1);
  // Invoke the actual competing lab handler during the unresolved domain request.
  h.get('lab-fixed').dispatch('click');
  await settle();
  assert.equal(h.requests.filter(request => request.path === '/api/lab').length, 0, 'No competing registration may be sent');
  assert.equal(h.get('lab-fixed').disabled, true, 'All launch buttons must disable while registration is pending');
  resolveRegistration({id:'first', origin:'https://first.test'});
  await settle();
  assert.equal(h.requests.filter(request => request.path === '/api/scans').length, 1, 'The first domain submission must still launch its scan');
  assert.equal(h.run('state.job.id'), 'first');
  assert.equal(h.run('state.site.id'), 'first');
});

test('a delayed history response cannot replace a newly active scan', async () => {
  const past = job('past', 'complete');
  let resolveHistory;
  const delayed = new Promise(resolve => { resolveHistory = resolve; });
  const h = harness(async path => { assert.equal(path, '/api/scans/past'); return delayed; });
  h.run(`state.scans = [${JSON.stringify(past)}]; history();`);
  h.get('history').children[0].dispatch('click');
  await settle();
  h.run(`setJob(${JSON.stringify(job('active', 'running'))}); beginPolling();`);
  const poll = h.run('state.poll');
  resolveHistory(past);
  await settle();
  assert.equal(h.run('state.job.id'), 'active');
  assert.equal(h.run('state.poll'), poll);
  assert.ok(h.timers.has(poll));
});

function allText(node) {
  return typeof node === 'string' ? node : [node.textContent || '', ...(node.children || []).map(allText)].join(' ');
}

test('a suspected custom finding keeps bilingual details, location and evidence', () => {
  const h = harness(async () => {});
  const finding = {title:'HTML girdisi', status:'suspected', severity:'medium', url:'https://example.test/search?q=masked',
    parameter:'q', repeats:2, note:'XSS yürütmesi doğrulanmadı.', condition:'Zararsız öğe oluştu.', impact:'Yansıma incelenmeli.',
    fix:'HTML kaçışı uygulayın.', steps:['Yapay kayıtla karşılaştırın.'], evidence:[{test:'Kontrol',http_status:200,sha256:'0123456789abcdef'}],
    location:{endpoint:'https://example.test/search',parameter:'q',method:'GET',response_line:3},
    english:{title:'HTML input',condition:'An inert element was parsed.',impact:'Execution was not verified.',fix:'Escape output.',steps:['Compare a synthetic record.']}};
  const card = h.run(`findingCard(${JSON.stringify(finding)})`);
  const text = allText(card);
  assert.ok(text.includes('Zararsız öğe oluştu.'), 'Turkish condition must remain visible');
  assert.ok(text.includes('An inert element was parsed.'), 'English explanation must be available');
  assert.ok(text.includes('Yapay kayıtla karşılaştırın.'), 'Suspected findings must retain reproduction steps');
  assert.ok(text.includes('0123456789abcdef'), 'Suspected findings must retain masked evidence');
  assert.ok(text.includes('q'), 'The affected parameter must be shown');
});

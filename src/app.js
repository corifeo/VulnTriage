/* VulnTriage app: SSVC triage queue, bucket board and flow builder. */
class Component extends DCLogic {
  constructor(props) {
    super(props);
    this.state = { tab: 'queue', qtab: 'todo', sel: 'CVE-2026-41872', ans: {}, records: {}, toast: null, flash: null, config: this.cisa(), seq: 100, skipped: {},
      importOpen: false, importErr: null, preview: null, replaceSample: false, imported: [], paste: '', importMeta: null,
      filterText: '', rationale: '', qpage: null, boardShow: {}, pasteOpen: false, replaceSampleApplied: false };
    const saved = this.loadSaved();
    if (saved) Object.assign(this.state, saved);
  }

  palette() { return ['#A7B0BE', '#6EA8FF', '#4FD1A5', '#F5B03D', '#FF7A59', '#C792EA']; }

  sources() {
    return [
      { id: 'manual', label: 'Manual only' },
      { id: 'kev', label: 'KEV + exploit references' },
      { id: 'cvss', label: 'CVSS exploitability metrics' },
      { id: 'impact', label: 'CVSS impact + CWE' },
      { id: 'assets', label: 'Asset inventory tags' }
    ];
  }

  cisa() {
    const steps = [
      { id: 'e', type: 'choice', name: 'Exploitation', question: 'What is the current state of exploitation?', source: 'kev',
        options: [{ id: 'none', label: 'None', desc: 'No evidence of exploitation or public PoC' }, { id: 'poc', label: 'Public PoC', desc: 'Exploit code or detailed method is public' }, { id: 'active', label: 'Active', desc: 'Reliable evidence of use in the wild' }] },
      { id: 'a', type: 'choice', name: 'Automatable', question: 'Can recon, weaponisation, delivery and exploitation be reliably automated?', source: 'cvss',
        options: [{ id: 'no', label: 'No', desc: 'At least one step needs a human or luck' }, { id: 'yes', label: 'Yes', desc: 'All four steps can be scripted at scale' }] },
      { id: 't', type: 'choice', name: 'Technical impact', question: 'How much control does a successful exploit give over the component?', source: 'impact',
        options: [{ id: 'partial', label: 'Partial', desc: 'Limited control or information disclosure' }, { id: 'total', label: 'Total', desc: 'Full control or total disclosure' }] },
      { id: 'mw', type: 'combine', name: 'Mission & well-being', question: 'Your context: how essential is the asset, and what harm could follow?', source: 'assets',
        inputs: [
          { id: 'mp', name: 'Mission prevalence', options: [{ id: 'minimal', label: 'Minimal', desc: 'Supports no essential function' }, { id: 'support', label: 'Support', desc: 'Supports essential functions indirectly' }, { id: 'essential', label: 'Essential', desc: 'Directly delivers an essential function' }] },
          { id: 'wb', name: 'Public well-being impact', options: [{ id: 'minimal', label: 'Minimal', desc: 'Negligible harm' }, { id: 'material', label: 'Material', desc: 'Noticeable financial or physical harm' }, { id: 'irreversible', label: 'Irreversible', desc: 'Severe or lasting harm' }] }
        ],
        outputs: [{ id: 'low', label: 'Low' }, { id: 'medium', label: 'Medium' }, { id: 'high', label: 'High' }],
        matrix: { 'minimal|minimal': 'low', 'minimal|material': 'medium', 'minimal|irreversible': 'high', 'support|minimal': 'medium', 'support|material': 'medium', 'support|irreversible': 'high', 'essential|minimal': 'high', 'essential|material': 'high', 'essential|irreversible': 'high' } }
    ];
    const buckets = [
      { id: 'track', name: 'Track', color: '#A7B0BE', sla: 'Standard patch cycle', desc: 'No action beyond normal processes.' },
      { id: 'trackstar', name: 'Track*', color: '#6EA8FF', sla: 'Standard cycle + watch', desc: 'Standard timeline; watch for changes.' },
      { id: 'attend', name: 'Attend', color: '#F5B03D', sla: 'Expedited', desc: 'Senior owner attention; faster than standard.' },
      { id: 'act', name: 'Act', color: '#FF7A59', sla: 'As soon as possible', desc: 'Leadership attention; immediate action.' }
    ];
    const T = {
      'none|no|partial': ['track','track','track'], 'none|no|total': ['track','track','trackstar'],
      'none|yes|partial': ['track','track','attend'], 'none|yes|total': ['track','track','attend'],
      'poc|no|partial': ['track','track','trackstar'], 'poc|no|total': ['track','trackstar','attend'],
      'poc|yes|partial': ['track','track','attend'], 'poc|yes|total': ['track','trackstar','attend'],
      'active|no|partial': ['track','track','attend'], 'active|no|total': ['track','attend','act'],
      'active|yes|partial': ['attend','attend','act'], 'active|yes|total': ['attend','act','act']
    };
    const table = {};
    Object.keys(T).forEach((k) => { ['low','medium','high'].forEach((m, i) => { table[k + '|' + m] = T[k][i]; }); });
    return { name: 'CISA SSVC', steps: steps, buckets: buckets, table: table,
      floors: [{ id: 'f1', enabled: false, step: 'e', value: 'active', bucket: 'attend' }] };
  }

  blank() {
    return { name: 'Custom flow', steps: [
      { id: 'q1', type: 'choice', name: 'New decision point', question: 'Describe what the analyst should decide', source: 'manual', options: [{ id: 'o1', label: 'No', desc: '' }, { id: 'o2', label: 'Yes', desc: '' }] }
    ], buckets: [
      { id: 'b1', name: 'Backlog', color: '#A7B0BE', sla: 'Next quarter', desc: 'Handled in normal maintenance.' },
      { id: 'b2', name: 'Fix fast', color: '#FF7A59', sla: '7 days', desc: 'Prioritised remediation.' }
    ], table: {}, floors: [] };
  }

  data() {
    return [
      { id: 'CVE-2026-41872', product: 'Edge VPN Gateway', short: 'unauthenticated RCE', title: 'Edge VPN Gateway: unauthenticated remote code execution via crafted HTTP request', age: '3d', cvss: '9.8', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-787 Out-of-bounds write', epss: '0.94', epssPct: '99.8', kev: true, kevDate: '4 Nov 2026', ransom: 'Known', exploits: '3 public', assets: '14', affected: '< 22.7R2.4', fixed: '22.7R2.4', summary: 'A stack overflow in the web portal lets a remote attacker run code as root before authentication. Mass scanning reported since disclosure.', adp: 'E:active · A:yes · TI:total',
        sug: { e: 'active', a: 'yes', t: 'total' }, ev: { e: 'KEV listed 4 Nov · EPSS 0.94 · 3 public exploits', a: 'AV:N · AC:L · PR:N · UI:N: end-to-end scriptable', t: 'Code execution as root on the appliance', mw: '14 internet-facing instances in customer remote access' } },
      { id: 'CVE-2026-43120', product: 'File transfer appliance', short: 'SQL injection to RCE', title: 'File transfer appliance: SQL injection in upload API leads to code execution', age: '2d', cvss: '9.8', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-89 SQL injection', epss: '0.87', epssPct: '99.5', kev: true, kevDate: '5 Nov 2026', ransom: 'Known', exploits: '2 public', assets: '2', affected: '< 2026.1.3', fixed: '2026.1.3', summary: 'Unauthenticated SQL injection allows web shell deployment. Data theft campaigns reported.', adp: 'E:active · A:yes · TI:total',
        sug: { e: 'active', a: 'yes', t: 'total' }, ev: { e: 'KEV listed 5 Nov · ransomware use known', a: 'Single unauthenticated request', t: 'Web shell, full host control', mw: '2 instances: partner file exchange' } },
      { id: 'CVE-2026-42011', product: 'Browser engine', short: 'type confusion in JIT', title: 'Browser engine: type confusion in JIT compiler leads to code execution', age: '1d', cvss: '8.8', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', cwe: 'CWE-843 Type confusion', epss: '0.41', epssPct: '97.1', kev: true, kevDate: '5 Nov 2026', ransom: 'Unknown', exploits: 'In the wild', assets: '3,120', affected: '< 131.0.6778', fixed: '131.0.6778', summary: 'A crafted page triggers type confusion in the JIT, giving code execution in the renderer. Exploited in targeted attacks.', adp: 'E:active · A:no · TI:total',
        sug: { e: 'active', a: 'no', t: 'total' }, ev: { e: 'Vendor confirms in-the-wild exploitation; KEV listed', a: 'UI:R: a user must visit a page', t: 'Arbitrary code in the renderer', mw: 'Managed desktop fleet, all staff' } },
      { id: 'CVE-2026-40355', product: 'SAML SDK', short: 'signature validation bypass', title: 'SAML SDK: assertion signature validation bypass', age: '5d', cvss: '9.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', cwe: 'CWE-347 Improper signature verification', epss: '0.04', epssPct: '88.0', kev: false, kevDate: '', ransom: 'n/a', exploits: 'None known', assets: '6', affected: '4.0.0 to 4.2.1', fixed: '4.2.2', summary: 'Wrapped assertions pass signature checks, letting an attacker impersonate any user of a relying app.', adp: 'E:none · A:yes · TI:partial',
        sug: { e: 'none', a: 'yes', t: 'partial' }, ev: { e: 'No KEV entry, no public PoC, EPSS 0.04', a: 'Network reachable, no auth, no interaction', t: 'Impersonation inside the relying app only', mw: '6 internal apps incl. customer portal SSO' } },
      { id: 'CVE-2026-39210', product: 'Java templating library', short: 'template injection', title: 'Java templating library: server-side template injection in expression parser', age: '9d', cvss: '8.1', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', cwe: 'CWE-1336 Template injection', epss: '0.31', epssPct: '96.4', kev: false, kevDate: '', ransom: 'n/a', exploits: '1 PoC', assets: '22', affected: '< 3.4.9', fixed: '3.4.9', summary: 'Untrusted input reaching template rendering can execute Java code, depending on how the app passes user data.', adp: 'E:poc · A:no · TI:total',
        sug: { e: 'poc', a: 'no', t: 'total' }, ev: { e: 'Public PoC on GitHub; not in KEV', a: 'AC:H: app-specific injection point', t: 'Java code execution in the app process', mw: '22 services via transitive dependency' } },
      { id: 'CVE-2026-38804', product: 'Container runtime', short: 'container escape', title: 'Container runtime: symlink race allows container escape', age: '13d', cvss: '8.6', vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', cwe: 'CWE-59 Link following', epss: '0.02', epssPct: '81.5', kev: false, kevDate: '', ransom: 'n/a', exploits: '1 PoC', assets: '410 nodes', affected: '< 1.2.6', fixed: '1.2.6', summary: 'A malicious image can win a race during mount and write to the host filesystem.', adp: 'E:poc · A:no · TI:total',
        sug: { e: 'poc', a: 'no', t: 'total' }, ev: { e: 'Researcher PoC; no in-the-wild reports', a: 'AV:L and UI:R: needs a malicious image run', t: 'Host root from inside a container', mw: 'All CI runners and production clusters' } },
      { id: 'CVE-2026-36188', product: 'Logging agent', short: 'path traversal', title: 'Logging agent: path traversal in config endpoint discloses files', age: '15d', cvss: '7.5', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', cwe: 'CWE-22 Path traversal', epss: '0.12', epssPct: '93.0', kev: false, kevDate: '', ransom: 'n/a', exploits: '1 PoC', assets: '1,850', affected: '< 9.4.1', fixed: '9.4.1', summary: 'The local management endpoint, if exposed, returns arbitrary files readable by the agent.', adp: 'E:poc · A:yes · TI:partial',
        sug: { e: 'poc', a: 'yes', t: 'partial' }, ev: { e: 'PoC in Metasploit module', a: 'Single request, no auth', t: 'File disclosure only', mw: 'Agent on every server; endpoint bound to localhost by default' } },
      { id: 'CVE-2026-37590', product: 'Message broker', short: 'pre-auth DoS', title: 'Message broker: malformed frame causes pre-auth denial of service', age: '17d', cvss: '7.5', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', cwe: 'CWE-400 Resource exhaustion', epss: '0.01', epssPct: '62.0', kev: false, kevDate: '', ransom: 'n/a', exploits: 'None known', assets: '8', affected: '< 3.13.4', fixed: '3.13.4', summary: 'A malformed protocol frame exhausts memory and crashes the broker before authentication.', adp: 'E:none · A:yes · TI:partial',
        sug: { e: 'none', a: 'yes', t: 'partial' }, ev: { e: 'No exploitation evidence', a: 'Single unauthenticated packet', t: 'Availability only', mw: 'Internal only, behind service mesh' } }
    ];
  }



  // ---------- persistence (this browser only) ----------
  storageKey() { return 'vulntriage:v1'; }
  loadSaved() {
    try {
      const raw = window.localStorage.getItem(this.storageKey());
      if (!raw) return null;
      const d = JSON.parse(raw);
      if (!d || !d.config || !Array.isArray(d.config.steps)) return null;
      const out = { config: d.config, records: d.records || {}, imported: d.imported || [], importMeta: d.importMeta || null, replaceSampleApplied: !!d.replaceSampleApplied, seq: d.seq || 100 };
      const all = (out.replaceSampleApplied && out.imported.length) ? out.imported : out.imported.concat(this.data());
      const firstOpen = all.find((v) => !out.records[v.id]) || all[0];
      if (firstOpen) out.sel = firstOpen.id;
      return out;
    } catch (_) { return null; }
  }
  saveNow() {
    clearTimeout(this._saveTimer); this._saveTimer = null;
    const st = this.state;
    try {
      window.localStorage.setItem(this.storageKey(), JSON.stringify({ config: st.config, records: st.records, imported: st.imported, importMeta: st.importMeta, replaceSampleApplied: st.replaceSampleApplied, seq: st.seq }));
    } catch (_) { /* storage full or blocked: keep working in memory */ }
  }
  componentDidUpdate() {
    if (!this._flushBound) {
      // A pending save must not be lost when the tab is hidden, reloaded or closed.
      this._flushBound = () => { if (this._saveTimer) this.saveNow(); };
      window.addEventListener('pagehide', this._flushBound);
      document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') this._flushBound(); });
    }
    clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => this.saveNow(), 300);
  }
  download(name, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  stamp() { return new Date().toISOString().slice(0, 10); }

  // ---------- import (VulnFlow triage export) ----------
  allVulns() {
    const imp = this.state.imported;
    if (this.state.replaceSampleApplied) return imp.length ? imp : this.data();
    const ids = {}; imp.forEach((v) => { ids[v.id] = true; });
    return imp.concat(this.data().filter((v) => !ids[v.id]));
  }

  fromExport(doc) {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Not a triage export: expected a JSON object.');
    if (doc.schema !== 'vulntriage.queue/v1') throw new Error('Unsupported schema "' + (doc.schema || 'missing') + '". Expected vulntriage.queue/v1 from VulnFlow TriageLoader.');
    if (!Array.isArray(doc.items)) throw new Error('The export has no items array.');
    const now = Date.now();
    const fmtDate = (iso) => { if (!iso) return ''; const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }); };
    const ageOf = (iso) => { const d = new Date(iso); if (!iso || isNaN(d)) return 'n/a'; const days = Math.max(0, Math.floor((now - d.getTime()) / 86400000)); return days < 60 ? days + 'd' : Math.round(days / 30) + 'mo'; };
    const cap = (s, n) => s && s.length > n ? s.slice(0, n - 1) + '…' : (s || '');
    return doc.items.filter((it) => it && typeof it.id === 'string').map((it) => {
      const p = it.product || {}, c = it.cvss || null, k = it.kev || {}, e = it.epss || null, ev = it.evidence || {};
      const prod = [p.vendor, p.name].filter(Boolean).join(' ') || 'Unknown product';
      const sug = {}, evt = {};
      if (ev.exploitation) { sug.e = ev.exploitation.value; evt.e = ev.exploitation.reason; }
      if (ev.automatable) { sug.a = ev.automatable.value; evt.a = ev.automatable.reason; }
      if (ev.technical_impact) { sug.t = ev.technical_impact.value; evt.t = ev.technical_impact.reason; }
      evt.mw = 'Not in public feeds: set from your asset context.';
      const short = it.title && it.title !== it.id ? it.title : cap(it.description, 60);
      return {
        id: it.id, imported: true, product: prod, short: cap(short.replace(prod + ' ', ''), 46), title: it.title || it.id,
        age: ageOf(it.published), cvss: c && c.score != null ? String(c.score) : 'n/a', cvssVer: c ? c.version : '',
        vector: c && c.vector ? c.vector : '', cwe: (it.cwe || []).join(', ') || 'No CWE',
        epss: e && e.probability != null ? e.probability.toFixed(2) : 'n/a', epssPct: e && e.percentile != null ? (e.percentile * 100).toFixed(1) : 'n/a',
        kev: !!k.listed, kevDate: fmtDate(k.date_added), ransom: k.listed ? (k.ransomware ? 'Known' : 'Unknown') : 'n/a',
        exploits: (it.exploit_refs || []).length ? (it.exploit_refs.length + ' tagged') : 'None tagged', assets: 'Not matched',
        affected: p.cpe_count ? p.cpe_count + ' CPE entries' : 'No CPE data', fixed: Array.isArray(p.fixed_in) ? (p.fixed_in.join(', ') || 'Unknown') : (p.fixed_in || 'Unknown'),
        summary: it.description || '', adp: 'Not in this export', sug: sug, ev: evt,
        refs: (it.references || []).slice(0, 4), nvdStatus: it.nvd_status || ''
      };
    });
  }

  readText(text, name) {
    let doc;
    try { doc = JSON.parse(text); } catch (err) { this.setState({ importErr: 'Could not parse JSON: ' + err.message, preview: null }); return; }
    try {
      const items = this.fromExport(doc);
      if (!items.length) { this.setState({ importErr: 'The export is valid but has no CVEs. Loosen the TriageLoader filters.', preview: null }); return; }
      this.setState({ importErr: null, preview: { doc: doc, items: items, fileName: name } });
    } catch (err) { this.setState({ importErr: err.message, preview: null }); }
  }

  readFile(file) {
    if (!file) return;
    if (file.size > 25 * 1024 * 1024) { this.setState({ importErr: 'File is over 25 MB. Use the limit option in TriageLoader.', preview: null }); return; }
    const r = new FileReader();
    r.onload = () => this.readText(String(r.result), file.name);
    r.onerror = () => this.setState({ importErr: 'Could not read the file.', preview: null });
    r.readAsText(file);
  }

  // ---------- engine ----------
  vals(s) { return s.type === 'combine' ? s.outputs : s.options; }
  valueOf(s, ans) {
    if (s.type === 'choice') return ans[s.id] || null;
    const a = ans[s.id + '.' + s.inputs[0].id], b = ans[s.id + '.' + s.inputs[1].id];
    if (!a || !b) return null;
    const v = s.matrix[a + '|' + b];
    return s.outputs.some((o) => o.id === v) ? v : s.outputs[0].id;
  }
  bucketValid(cfg, id) { return cfg.buckets.some((b) => b.id === id); }
  lookup(cfg, key) { const v = cfg.table[key]; return this.bucketValid(cfg, v) ? v : cfg.buckets[0].id; }
  decide(cfg, ans) {
    if (!cfg.buckets.length) return null;
    const vs = cfg.steps.map((s) => this.valueOf(s, ans));
    if (vs.some((v) => !v)) return null;
    let b = this.lookup(cfg, vs.join('|'));
    let floor = null;
    const rank = (id) => cfg.buckets.findIndex((x) => x.id === id);
    cfg.floors.forEach((f) => {
      if (!f.enabled || !this.bucketValid(cfg, f.bucket)) return;
      const idx = cfg.steps.findIndex((s) => s.id === f.step);
      if (idx < 0 || vs[idx] !== f.value) return;
      if (rank(f.bucket) > rank(b)) { b = f.bucket; floor = f; }
    });
    return { bucket: b, floor: floor, vs: vs };
  }
  cart(lists) { return lists.reduce((acc, l) => { const out = []; acc.forEach((a) => l.forEach((x) => out.push(a.concat([x])))); return out; }, [[]]); }

  upd(fn) { const c = JSON.parse(JSON.stringify(this.state.config)); fn(c); this.setState({ config: c }); }
  nid(p) { const n = this.state.seq + 1; this.setState({ seq: n }); return p + n; }

  open(id) {
    const r = this.state.records[id];
    this.setState({ sel: id, ans: r ? Object.assign({}, r.ans) : {}, rationale: r && r.rationale ? r.rationale : '', tab: 'queue', toast: null, qpage: null });
  }

  renderVals() {
    const st = this.state, cfg = st.config, V = this.allVulns();
    const PAL = this.palette();
    const bById = {}; cfg.buckets.forEach((b) => { bById[b.id] = b; });
    const recBucket = (id) => { const r = st.records[id]; return r && bById[r.bucket] ? r.bucket : null; };
    const cur = V.find((v) => v.id === st.sel) || V[0];
    const ans = st.ans;
    const res = this.decide(cfg, ans);
    const out = res ? res.bucket : null;
    // Most new CVEs have no CPE data yet; show the title alone rather than "Unknown product: ...".
    const rowLabel = (v) => v.product && v.product !== 'Unknown product' ? v.product + ': ' + v.short : (v.title && v.title.length > 72 ? v.title.slice(0, 71) + '…' : (v.title || v.short));
    const cvssStyle = (c) => { c = parseFloat(c); return c >= 9 ? 'background: #3B1A14; color: #FF9C80' : (c >= 7 ? 'background: #3A2A10; color: #FFC85C' : 'background: #1A1F28; color: #C3CAD5'); };
    const fill = (b) => 'background: ' + b.color + '; color: #0B0E13';

    // tabs
    const untriaged = V.filter((v) => !recBucket(v.id));
    const done = V.filter((v) => recBucket(v.id));
    const tabs = [['queue', 'Triage queue', untriaged.length], ['board', 'Buckets', null], ['config', 'Configure', null]].map((t) => ({
      label: t[1], hasCount: t[2] !== null, count: t[2], current: st.tab === t[0] ? 'page' : 'false',
      style: st.tab === t[0] ? 'background: #1A2A44; color: #FFFFFF' : 'background: transparent; color: #9AA4B2',
      pick: () => this.setState({ tab: t[0] })
    }));

    const bucketStrip = cfg.buckets.map((b) => ({ name: b.name, count: done.filter((v) => recBucket(v.id) === b.id).length, dot: 'background: ' + b.color,
      pulse: st.flash === b.id ? 'border-color: ' + b.color + '; box-shadow: 0 0 0 3px ' + b.color + '33; transform: translateY(-2px)' : '' }));

    // queue list
    const q = (st.filterText || '').trim().toLowerCase();
    const listSrc = (st.qtab === 'todo' ? untriaged : done).filter((v) => !q || [v.id, v.product, v.short, v.cwe, v.title].join(' ').toLowerCase().includes(q));
    const PAGE = 20;
    const pages = Math.max(1, Math.ceil(listSrc.length / PAGE));
    const curIdx = listSrc.findIndex((v) => v.id === cur.id);
    const page = st.qpage == null ? (curIdx >= 0 ? Math.floor(curIdx / PAGE) : 0) : Math.max(0, Math.min(st.qpage, pages - 1));
    const pageStart = page * PAGE, pageEnd = Math.min(listSrc.length, pageStart + PAGE);
    const goPage = (n) => this.setState({ qpage: Math.max(0, Math.min(n, pages - 1)) });
    const listTotal = st.qtab === 'todo' ? untriaged.length : done.length;
    const pager = { hasPager: pages > 1, pageText: (pageStart + 1) + '–' + pageEnd + ' of ' + listSrc.length, pageLabel: 'Page ' + (page + 1) + ' of ' + pages,
      atFirst: page === 0, atLast: page >= pages - 1, firstPage: () => goPage(0), prevPage: () => goPage(page - 1), nextPage: () => goPage(page + 1), lastPage: () => goPage(pages - 1),
      listCount: q ? listSrc.length + ' of ' + listTotal + ' match' : listTotal + (listTotal === 1 ? ' CVE' : ' CVEs') + (pages > 1 ? ' · ' + PAGE + ' per page' : '') };
    const qlist = listSrc.slice(pageStart, pageEnd).map((v) => {
      const b = recBucket(v.id);
      return Object.assign({}, v, { label: rowLabel(v), pick: () => this.open(v.id),
        rowStyle: v.id === cur.id ? 'background: #18233A; box-shadow: inset 3px 0 0 #6EA8FF' : 'background: transparent',
        cvssStyle: cvssStyle(v.cvss), hasBucket: !!b, bucketName: b ? bById[b].name : '', bucketStyle: b ? fill(bById[b]) : '' });
    });
    const qtabs = [['todo', 'To triage (' + untriaged.length + ')'], ['done', 'Done (' + done.length + ')']].map((q) => ({ label: q[1], pick: () => this.setState({ qtab: q[0], qpage: 0 }),
      style: st.qtab === q[0] ? 'background: #1A2A44; border: 1px solid #3D5F94; color: #FFFFFF' : 'background: transparent; border: 1px solid #2A3240; color: #9AA4B2' }));

    // steps
    const optStyle = (sel, locked) => sel ? 'background: #1A2A44; border: 1.5px solid #6EA8FF; color: #FFFFFF; box-shadow: 0 0 0 4px rgba(110,168,255,.12)'
      : (locked ? 'background: #10141A; border: 1.5px solid #1F2631; color: #6B7586; cursor: not-allowed' : 'background: #151A22; border: 1.5px solid #2A3240; color: #E6EAF0');
    const setAns = (k, v) => { const a = Object.assign({}, this.state.ans); a[k] = v; this.setState({ ans: a }); };
    const srcLabel = {}; this.sources().forEach((s) => { srcLabel[s.id] = s.label; });
    const vsNow = cfg.steps.map((s) => this.valueOf(s, ans));
    const activeIdx = vsNow.findIndex((v) => !v);
    const steps = cfg.steps.map((s, i) => {
      const locked = vsNow.slice(0, i).some((v) => !v);
      const isActive = i === activeIdx;
      const sug = s.source !== 'manual' && cur.sug[s.id] ? cur.sug[s.id] : null;
      const mk = (key, opts, sg) => opts.map((o) => ({ label: o.label, desc: o.desc || '', suggested: sg === o.id, pressed: ans[key] === o.id ? 'true' : 'false',
        style: optStyle(ans[key] === o.id, locked), pick: () => setAns(key, o.id) }));
      const groups = s.type === 'choice' ? [{ hasLabel: false, label: '', options: mk(s.id, s.options, sug) }]
        : s.inputs.map((inp) => ({ hasLabel: true, label: inp.name, options: mk(s.id + '.' + inp.id, inp.options, null) }));
      const v = vsNow[i];
      const vl = v ? (this.vals(s).find((o) => o.id === v) || {}).label : '';
      return { name: s.name, question: s.question, groups: groups, locked: locked, hasValue: !!v, valueLabel: s.type === 'combine' && v ? 'Result: ' + vl : vl,
        sourceLabel: s.source === 'manual' ? 'Manual' : 'Evidence', evidence: s.source === 'manual' ? 'No feed mapped to this point; analyst decides.' : (cur.ev[s.id] || 'No evidence found in connected feeds for this point.'),
        num: v ? '✓' : String(i + 1),
        cardStyle: locked ? 'background: #10141A; border: 1px solid #1C222C; opacity: .5' : (isActive ? 'background: #12161D; border: 1px solid #3D5F94; box-shadow: 0 0 0 4px rgba(110,168,255,.07), 0 12px 32px rgba(0,0,0,.35)' : 'background: #12161D; border: 1px solid #252C38'),
        numStyle: v ? 'background: #6EA8FF; color: #0B0E13' : (isActive ? 'background: #1A2A44; color: #BFD7FF; border: 1.5px solid #6EA8FF' : 'background: #1A1F28; color: #9AA4B2') };
    });
    const path = cfg.steps.map((s, i) => { const v = vsNow[i]; const lbl = v ? (this.vals(s).find((o) => o.id === v) || {}).label : null;
      return { n: i + 1, k: s.name, kNb: s.name.replace(/-/g, '\u2011'), v: lbl || '?', style: lbl ? 'background: #1A2A44; border: 1px solid #3D5F94; color: #E6EAF0' : 'background: #10141A; border: 1px dashed #2E3644; color: #6B7586' }; });

    const buckets = cfg.buckets.map((b) => { const on = out === b.id; return { name: b.name, desc: b.desc || '', sla: b.sla || 'Not set',
      style: on ? fill(b) + '; border: 1px solid ' + b.color + '; transform: translateY(-3px); box-shadow: 0 14px 30px rgba(0,0,0,.4)'
        : (out ? 'background: #10141A; border: 1px solid #1F2631; color: #6B7586; opacity: .55' : 'background: #151A22; border: 1px solid #2A3240; color: ' + b.color),
      textStyle: on ? 'color: #0B0E13' : 'color: #9AA4B2' }; });

    const ab = (s) => s.name.split(/[^A-Za-z]+/).filter(Boolean).map((w) => w[0]).join('').toUpperCase().slice(0, 2) || 'X';
    const vector = cfg.steps.map((s, i) => { const v = vsNow[i]; const l = v ? (this.vals(s).find((o) => o.id === v) || { label: '?' }).label : '?'; return ab(s) + ':' + l.replace(/\s+/g, ''); }).join('/') + '/D:' + (out ? bById[out].name : '?');

    const nextUntriaged = (exclude) => { const l = V.filter((v) => !recBucket(v.id) && v.id !== exclude && !st.skipped[v.id]); return l.length ? l[0] : (V.find((v) => !recBucket(v.id) && v.id !== exclude) || null); };

    const record = () => {
      if (!out) return;
      const recs = Object.assign({}, st.records); recs[cur.id] = { bucket: out, ans: Object.assign({}, ans), vec: vector, rationale: st.rationale || '', decidedAt: new Date().toISOString() };
      const nx = V.filter((v) => !(recs[v.id] && bById[recs[v.id].bucket]) && v.id !== cur.id);
      const n = nx.length ? nx[0] : null;
      this.setState({ records: recs, flash: out, toast: { text: cur.id + ' moved to ' + bById[out].name + (n ? '. Next: ' + n.id : '. Queue clear.'), color: bById[out].color },
        sel: n ? n.id : cur.id, ans: n ? {} : ans, rationale: n ? '' : st.rationale, qpage: null });
      setTimeout(() => this.setState({ flash: null }), 900);
    };
    const skip = () => { const sk = Object.assign({}, st.skipped); sk[cur.id] = true; const n = V.filter((v) => !recBucket(v.id) && !sk[v.id])[0]; if (n) this.setState({ skipped: sk, sel: n.id, ans: {}, rationale: '', toast: null, qpage: null }); else this.setState({ skipped: {}, toast: null }); };

    const acceptSuggested = () => { const a = Object.assign({}, this.state.ans); cfg.steps.forEach((s) => { if (s.type === 'choice' && s.source !== 'manual' && cur.sug[s.id] && s.options.some((o) => o.id === cur.sug[s.id])) a[s.id] = cur.sug[s.id]; }); this.setState({ ans: a }); };

    // attack chain
    const m = {}; (cur.vector || '').split('/').slice(1).forEach((p) => { const kv = p.split(':'); m[kv[0]] = kv[1]; });
    const AV = { N: ['Network', 'Reachable remotely over the network', 'hi'], A: ['Adjacent', 'Needs a shared network segment', 'mid'], L: ['Local', 'Needs local access or a malicious file or image', 'lo'], P: ['Physical', 'Needs physical access', 'lo'] };
    const AC = { L: ['Low', 'No special conditions to win', 'hi'], H: ['High', 'Depends on conditions outside attacker control', 'lo'] };
    const PR = { N: ['None', 'No account needed', 'hi'], L: ['Low', 'Basic user account', 'mid'], H: ['High', 'Admin account needed', 'lo'] };
    const UI = { N: ['None', 'No victim action needed', 'hi'], R: ['Required', 'A user must click, open or run something', 'lo'] };
    const SC = { U: ['Unchanged', 'Impact stays in the vulnerable component', 'mid'], C: ['Changed', 'Breaks out into other components', 'hi'] };
    const tone = (t) => t === 'hi' ? 'color: #FF9C80' : (t === 'mid' ? 'color: #FFC85C' : 'color: #A7B0BE');
    const dotT = (t) => t === 'hi' ? 'background: #FF7A59' : (t === 'mid' ? 'background: #F5B03D' : 'background: #4B5566');
    UI.P = ['Passive', 'Victim takes a normal action', 'mid']; UI.A = ['Active', 'Victim must take a deliberate action', 'lo'];
    const NA = ['Unknown', 'Not in the vector', 'lo'];
    const rows = [['Entry point', AV[m.AV] || NA], ['Complexity', AC[m.AC] || NA], ['Privileges', PR[m.PR] || NA], ['User interaction', UI[m.UI] || NA]]
      .concat(m.S ? [['Scope', SC[m.S] || NA]] : (m.AT ? [['Attack requirements', m.AT === 'N' ? ['None', 'No preconditions on the target', 'hi'] : ['Present', 'Depends on target conditions', 'lo']]] : []));
    const chain = rows.map((r, i) => ({ k: r[0], v: r[1][0], note: r[1][1], valStyle: tone(r[1][2]), dot: dotT(r[1][2]), line: i < rows.length - 1 }));
    const LV = { H: ['High', '100%', '#FF7A59'], L: ['Low', '45%', '#F5B03D'], N: ['None', '4%', '#4B5566'] };
    const LVx = (x) => LV[x] || ['n/a', '0%', '#4B5566'];
    const cia = [['Confidentiality', m.C || m.VC], ['Integrity', m.I || m.VI], ['Availability', m.A || m.VA]].map((r) => ({ k: r[0], v: LVx(r[1])[0], bar: 'width: ' + LVx(r[1])[1] + '; background: ' + LVx(r[1])[2] }));

    // board
    const card = (v) => { const r = st.records[v.id]; return Object.assign({}, v, { label: rowLabel(v), open: () => this.open(v.id), cvssStyle: cvssStyle(v.cvss), hasVec: !!(r && recBucket(v.id)), vec: r ? r.vec : '' }); };
    const COL = 25;
    const board = [{ key: '_todo', name: 'To triage', sla: 'Awaiting decision', headStyle: 'background: #1A1F28; color: #E6EAF0', all: untriaged }]
      .concat(cfg.buckets.map((b) => ({ key: b.id, name: b.name, sla: b.sla || '', headStyle: fill(b), all: done.filter((v) => recBucket(v.id) === b.id) })))
      .map((c) => { const shown = Math.min(c.all.length, (st.boardShow || {})[c.key] || COL); const hidden = c.all.length - shown;
        return Object.assign(c, { count: c.all.length, empty: c.all.length === 0, cards: c.all.slice(0, shown).map(card), hasMore: hidden > 0,
          moreText: 'Show ' + Math.min(hidden, 50) + ' more (' + hidden + ' hidden)',
          showMore: () => { const bs = Object.assign({}, st.boardShow); bs[c.key] = shown + 50; this.setState({ boardShow: bs }); } }); });

    // ---------- configure ----------
    const n = cfg.steps.length;
    const points = cfg.steps.map((s, i) => {
      const base = { num: String(i + 1), name: s.name, question: s.question, source: s.source, isChoice: s.type === 'choice', isCombine: s.type === 'combine',
        kind: s.type === 'choice' ? 'Choice' : 'Combined', kindStyle: s.type === 'choice' ? 'background: #1A2A44; color: #BFD7FF' : 'background: #231D3A; color: #D9CCFF',
        setName: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].name = v; }); },
        setQuestion: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].question = v; }); },
        sourceLabel: (this.sources().find((x) => x.id === s.source) || { label: 'Manual only' }).label,
        cycleSource: () => { const L = this.sources(); const k = L.findIndex((x) => x.id === s.source); this.upd((c) => { c.steps[i].source = L[(k + 1) % L.length].id; }); },
        mCols: '',
        noUp: i === 0, noDown: i === n - 1, noRemove: n <= 1,
        up: () => this.moveStep(i, i - 1), down: () => this.moveStep(i, i + 1), remove: () => this.removeStep(i),
        options: [], inputs: [], outputs: [], mHead: [], mRows: [], rowAxis: '', colAxis: '' };
      if (s.type === 'choice') {
        base.options = s.options.map((o, j) => ({ label: o.label, noRemove: s.options.length <= 2,
          setLabel: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].options[j].label = v; }); },
          remove: () => this.upd((c) => { c.steps[i].options.splice(j, 1); }) }));
        base.addOption = () => { const id = 'o' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 1 }); this.upd((c) => { c.steps[i].options.push({ id: id, label: 'Option ' + (c.steps[i].options.length + 1), desc: '' }); }); };
      } else {
        base.inputs = s.inputs.map((inp, k) => ({ name: inp.name,
          setName: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].inputs[k].name = v; }); },
          addOption: () => { const id = 'o' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 1 }); this.upd((c) => { c.steps[i].inputs[k].options.push({ id: id, label: 'Option ' + (c.steps[i].inputs[k].options.length + 1), desc: '' }); }); },
          options: inp.options.map((o, j) => ({ label: o.label, noRemove: inp.options.length <= 2,
            setLabel: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].inputs[k].options[j].label = v; }); },
            remove: () => this.upd((c) => { c.steps[i].inputs[k].options.splice(j, 1); }) })) }));
        base.outputs = s.outputs.map((o, j) => ({ label: o.label, noRemove: s.outputs.length <= 2,
          setLabel: (e) => { const v = e.target.value; this.upd((c) => { c.steps[i].outputs[j].label = v; }); },
          remove: () => this.upd((c) => { c.steps[i].outputs.splice(j, 1); }) }));
        base.addOutput = () => { const id = 'r' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 1 }); this.upd((c) => { c.steps[i].outputs.push({ id: id, label: 'Level ' + (c.steps[i].outputs.length + 1) }); }); };
        base.rowAxis = s.inputs[0].name; base.colAxis = s.inputs[1].name;
        base.mCols = 'grid-template-columns: 96px repeat(' + s.inputs[1].options.length + ', minmax(76px, 1fr))';
        base.mHead = s.inputs[1].options.map((o) => ({ label: o.label }));
        const shade = ['#1A1F28', '#2A3A55', '#3D5F94', '#5B7FC0', '#7FA2E0', '#A9C4F0'];
        base.mRows = s.inputs[0].options.map((a) => ({ label: a.label, cells: s.inputs[1].options.map((b) => {
          const key = a.id + '|' + b.id; let oi = s.outputs.findIndex((o) => o.id === s.matrix[key]); if (oi < 0) oi = 0;
          const tc = oi >= 3 ? '#0B0E13' : '#E6EAF0';
          return { label: s.outputs[oi].label, style: 'background: ' + shade[Math.min(oi, 5)] + '; color: ' + tc + '; border: 1px solid #2A3240',
            cycle: () => this.upd((c) => { const st2 = c.steps[i]; st2.matrix[key] = st2.outputs[(oi + 1) % st2.outputs.length].id; }) }; }) }));
      }
      return base;
    });

    const bucketCfg = cfg.buckets.map((b, i) => ({ name: b.name, sla: b.sla,
      used: Object.keys(cfg.table).length ? this.countPaths(cfg, b.id) : 0,
      edge: 'box-shadow: inset 4px 0 0 ' + b.color,
      setName: (e) => { const v = e.target.value; this.upd((c) => { c.buckets[i].name = v; }); },
      setSla: (e) => { const v = e.target.value; this.upd((c) => { c.buckets[i].sla = v; }); },
      noUp: i === 0, noDown: i === cfg.buckets.length - 1, noRemove: cfg.buckets.length <= 1,
      up: () => this.upd((c) => { const t = c.buckets[i]; c.buckets[i] = c.buckets[i - 1]; c.buckets[i - 1] = t; }),
      down: () => this.upd((c) => { const t = c.buckets[i]; c.buckets[i] = c.buckets[i + 1]; c.buckets[i + 1] = t; }),
      remove: () => this.upd((c) => { c.buckets.splice(i, 1); }),
      swatches: PAL.map((col) => ({ label: 'Colour ' + col, style: 'background: ' + col + '; border: 2px solid ' + (b.color === col ? '#FFFFFF' : 'transparent'),
        pick: () => this.upd((c) => { c.buckets[i].color = col; }) })) }));

    const floors = cfg.floors.map((f, i) => {
      const si = Math.max(0, cfg.steps.findIndex((x) => x.id === f.step)); const s = cfg.steps[si];
      const vl = this.vals(s); const vi = Math.max(0, vl.findIndex((o) => o.id === f.value));
      const bi = Math.max(0, cfg.buckets.findIndex((b) => b.id === f.bucket)); const b = cfg.buckets[bi];
      return { pressed: f.enabled ? 'true' : 'false',
        trackStyle: f.enabled ? 'background: #6EA8FF' : 'background: #2A3240',
        knobStyle: f.enabled ? 'margin-left: 16px' : 'margin-left: 0',
        stepLabel: s.name, valueLabel: vl[vi].label, bucketLabel: b.name, bucketStyle: 'background: ' + b.color + '; color: #0B0E13',
        toggle: () => this.upd((c) => { c.floors[i].enabled = !c.floors[i].enabled; }),
        cycleStep: () => this.upd((c) => { const ns = c.steps[(si + 1) % c.steps.length]; c.floors[i].step = ns.id; c.floors[i].value = this.vals(ns)[0].id; }),
        cycleValue: () => this.upd((c) => { c.floors[i].step = s.id; c.floors[i].value = vl[(vi + 1) % vl.length].id; }),
        cycleBucket: () => this.upd((c) => { c.floors[i].bucket = c.buckets[(bi + 1) % c.buckets.length].id; }),
        remove: () => this.upd((c) => { c.floors.splice(i, 1); }) }; });

    // policy table
    const last = cfg.steps[n - 1];
    const rowDims = cfg.steps.slice(0, n - 1);
    let combos = this.cart(rowDims.map((s) => this.vals(s)));
    const total = combos.length * this.vals(last).length;
    const capped = combos.length > 120;
    if (capped) combos = combos.slice(0, 120);
    const policyHead = rowDims.map((s) => ({ label: s.name, style: 'color: #9AA4B2' }))
      .concat(this.vals(last).map((o) => ({ label: last.name + ': ' + o.label, style: 'color: #BFD7FF; text-align: center' })));
    const policyRows = combos.map((combo, ri) => ({
      keys: combo.map((o, ci) => ({ label: o.label, style: (ci === 0 ? 'border-radius: 8px 0 0 8px; ' : '') + ((ri > 0 && combos[ri - 1][ci].id === o.id && combo.slice(0, ci).every((x, xi) => combos[ri - 1][xi].id === x.id)) ? 'color: #4B5566' : '') })),
      outs: this.vals(last).map((o) => { const key = combo.map((x) => x.id).concat([o.id]).join('|'); const bid = this.lookup(cfg, key); const b = bById[bid]; const bi = cfg.buckets.findIndex((x) => x.id === bid);
        return { label: b ? b.name : '?', style: b ? 'background: ' + b.color + '; color: #0B0E13; border: 0' : '',
          cycle: () => this.upd((c) => { c.table[key] = c.buckets[(bi + 1) % c.buckets.length].id; }) }; })
    }));

    const addChoice = () => { const id = 'q' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 2 });
      this.upd((c) => { const opts = [{ id: 'y', label: 'Yes', desc: '' }, { id: 'n', label: 'No', desc: '' }];
        const nt = {}; Object.keys(c.table).forEach((k) => opts.forEach((o) => { nt[k + '|' + o.id] = c.table[k]; })); c.table = nt;
        c.steps.push({ id: id, type: 'choice', name: 'New decision point', question: 'What should the analyst decide here?', source: 'manual', options: opts }); }); };
    const addCombine = () => { const id = 'c' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 2 });
      this.upd((c) => { const outs = [{ id: 'lo', label: 'Low' }, { id: 'hi', label: 'High' }];
        const nt = {}; Object.keys(c.table).forEach((k) => outs.forEach((o) => { nt[k + '|' + o.id] = c.table[k]; })); c.table = nt;
        c.steps.push({ id: id, type: 'combine', name: 'New combined point', question: 'Two questions that resolve to one level', source: 'manual',
          inputs: [{ id: 'x', name: 'First question', options: [{ id: 'a', label: 'Low' }, { id: 'b', label: 'High' }] }, { id: 'y', name: 'Second question', options: [{ id: 'a', label: 'Low' }, { id: 'b', label: 'High' }] }],
          outputs: outs, matrix: { 'a|a': 'lo', 'a|b': 'hi', 'b|a': 'hi', 'b|b': 'hi' } }); }); };
    const addBucket = () => { const id = 'b' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 1 });
      this.upd((c) => { c.buckets.push({ id: id, name: 'New bucket', color: PAL[c.buckets.length % PAL.length], sla: '', desc: '' }); }); };
    const addFloor = () => { const id = 'f' + (this.state.seq + 1); this.setState({ seq: this.state.seq + 1 });
      this.upd((c) => { const s = c.steps[0]; c.floors.push({ id: id, enabled: true, step: s.id, value: this.vals(s)[this.vals(s).length - 1].id, bucket: c.buckets[c.buckets.length - 1].id }); }); };

    const toast = st.toast;
    const curB = recBucket(cur.id);
    const pos = untriaged.findIndex((v) => v.id === cur.id);

    return {
      importOpen: st.importOpen,
      openImport: () => this.setState({ importOpen: true, importErr: null, preview: null }),
      closeImport: () => this.setState({ importOpen: false }),
      dragOver: (e) => { e.preventDefault(); },
      dropFile: (e) => { e.preventDefault(); const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]; this.readFile(f); },
      pickFile: (e) => { const f = e.target.files && e.target.files[0]; this.readFile(f); e.target.value = ''; },
      setPaste: (e) => { this.setState({ paste: e.target.value }); },
      parsePaste: () => this.readText(this.state.paste || '', 'Pasted JSON'),
      importHasError: !!st.importErr, importError: st.importErr || '',
      importHasPreview: !!st.preview,
      pv: this.previewVals(),
      toggleReplace: () => this.setState({ replaceSample: !this.state.replaceSample }),
      confirmImport: () => {
        const pvw = this.state.preview; if (!pvw) return;
        const replace = this.state.replaceSample;
        const byId = {}; (replace ? [] : this.state.imported).forEach((v) => { byId[v.id] = v; });
        let added = 0, updated = 0;
        pvw.items.forEach((v) => { if (byId[v.id]) updated++; else added++; byId[v.id] = v; });
        const imported = pvw.items.concat((replace ? [] : this.state.imported).filter((v) => !pvw.items.some((x) => x.id === v.id)));
        const first = imported.find((v) => !this.state.records[v.id]) || imported[0];
        this.setState({ imported: imported, replaceSampleApplied: replace || this.state.replaceSampleApplied, importOpen: false, preview: null, tab: 'queue', qtab: 'todo', paste: '', pasteOpen: false, filterText: '',
          sel: first.id, ans: {}, rationale: '', importMeta: { name: pvw.fileName, generated: pvw.doc.generated_at, count: imported.length },
          toast: { text: 'Imported ' + added + ' new' + (updated ? ', updated ' + updated : '') + ' from ' + pvw.fileName, color: '#6EA8FF' } });
      },
      sourceDot: st.importMeta ? 'background: #4FD1A5' : 'background: #F5B03D',
      sourceText: st.importMeta ? st.importMeta.count + ' imported from ' + st.importMeta.name : 'Sample data · nothing imported',
      filterText: st.filterText, setFilter: (e) => this.setState({ filterText: e.target.value, qpage: 0 }),
      rationale: st.rationale, setRationale: (e) => this.setState({ rationale: e.target.value }),
      pasteOpen: st.pasteOpen, pasteExpanded: st.pasteOpen ? 'true' : 'false', pasteVal: st.paste,
      togglePaste: () => this.setState({ pasteOpen: !this.state.pasteOpen }),
      loadDemo: () => {
        fetch('examples/triage-queue-demo.json').then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
          .then((txt) => this.readText(txt, 'triage-queue-demo.json'))
          .catch(() => this.setState({ importErr: 'Could not load the demo file. Serve the folder over HTTP (for example: python3 -m http.server) rather than opening index.html directly.' }));
      },
      exportDecisions: () => {
        const all = this.allVulns(); const byId = {}; all.forEach((v) => { byId[v.id] = v; });
        const decisions = Object.keys(st.records).filter((id) => bById[st.records[id].bucket]).map((id) => {
          const r = st.records[id];
          return { id: id, title: byId[id] ? byId[id].title : null, bucket: bById[r.bucket].name, bucket_id: r.bucket, vector: r.vec, answers: r.ans, rationale: r.rationale || '', decided_at: r.decidedAt || null };
        });
        this.download('vulntriage-decisions-' + this.stamp() + '.json', { schema: 'vulntriage.decisions/v1', exported_at: new Date().toISOString(), flow: cfg.name, count: decisions.length, decisions: decisions });
      },
      exportConfig: () => this.download('vulntriage-flow-' + this.stamp() + '.json', { schema: 'vulntriage.flow/v1', flow: cfg }),
      importConfig: (e) => {
        const f = e.target.files && e.target.files[0]; e.target.value = ''; if (!f) return;
        const r = new FileReader();
        r.onload = () => {
          try {
            const d = JSON.parse(String(r.result));
            const flow = d && d.schema === 'vulntriage.flow/v1' ? d.flow : null;
            if (!flow || !Array.isArray(flow.steps) || !Array.isArray(flow.buckets) || !flow.buckets.length) throw new Error('bad');
            flow.floors = flow.floors || []; flow.table = flow.table || {};
            this.setState({ config: flow, ans: {}, toast: { text: 'Loaded flow "' + flow.name + '"', color: '#6EA8FF' } });
          } catch (_) { this.setState({ toast: { text: 'That file is not a VulnTriage flow export (vulntriage.flow/v1).', color: '#FF7A59' } }); }
        };
        r.readAsText(f);
      },
      clearSaved: () => {
        if (!window.confirm('Clear the saved flow, decisions and imports from this browser?')) return;
        try { window.localStorage.removeItem(this.storageKey()); } catch (_) { /* ignore */ }
        this.setState({ config: this.cisa(), records: {}, imported: [], importMeta: null, replaceSampleApplied: false, sel: 'CVE-2026-41872', ans: {}, rationale: '', skipped: {}, toast: null });
      },
      tabs: tabs, isQueue: st.tab === 'queue', isBoard: st.tab === 'board', isConfig: st.tab === 'config',
      flowName: cfg.name, setFlowName: (e) => { const v = e.target.value; this.upd((c) => { c.name = v; }); },
      untriagedCount: untriaged.length, bucketStrip: bucketStrip,
      qtabs: qtabs, qlist: qlist, pager: pager, listEmpty: qlist.length === 0, listEmptyText: q ? 'Nothing matches "' + st.filterText + '".' : (st.qtab === 'todo' ? 'Queue clear. Nothing left to triage.' : 'No decisions recorded yet.'),
      hasToast: !!toast, toast: toast ? toast.text : '', toastStyle: toast ? 'background: ' + toast.color + '; color: #0B0E13' : '',
      cur: Object.assign({}, cur, { kevText: cur.kev ? 'Listed ' + cur.kevDate : 'Not listed', cvssVerLabel: cur.cvssVer || '3.1' }),
      curHasBucket: !!curB, curBucketName: curB ? bById[curB].name : '', curBucketStyle: curB ? fill(bById[curB]) : '',
      queuePos: pos >= 0 ? (pos + 1) + ' of ' + untriaged.length + ' in queue' : 'Already triaged',
      steps: steps, path: path,
      outcomeLabel: out ? bById[out].name : 'Pending',
      outcomeChip: out ? fill(bById[out]) + '; border: 1px solid ' + bById[out].color : 'background: #10141A; border: 1px dashed #2E3644; color: #9AA4B2',
      outcomeHint: out ? 'From the ' + cfg.name + ' policy' : 'Complete every decision point',
      buckets: buckets, vector: vector,
      hasFloorNote: !!(res && res.floor), floorNote: res && res.floor ? 'Override rule raised this to ' + bById[res.floor.bucket].name + '.' : '',
      chain: chain, cia: cia, epssBar: 'width: ' + (Math.round(parseFloat(cur.epss) * 100) || 0) + '%',
      notComplete: !out, recordLabel: out ? (curB ? 'Update: move to ' + bById[out].name : 'Move to ' + bById[out].name) : 'Move to bucket',
      recordStyle: out ? fill(bById[out]) : 'background: #1A1F28; color: #6B7586; cursor: not-allowed',
      acceptSuggested: acceptSuggested, resetAnswers: () => this.setState({ ans: {} }), record: record, skip: skip,
      board: board,
      stats: { points: n, paths: total, buckets: cfg.buckets.length, rules: cfg.floors.filter((f) => f.enabled).length },
      sources: this.sources(), points: points, bucketCfg: bucketCfg, floors: floors,
      policyHead: policyHead, policyRows: policyRows,
      policyCols: 'grid-template-columns: ' + (rowDims.length ? 'repeat(' + rowDims.length + ', minmax(110px, 1fr)) ' : '') + 'repeat(' + this.vals(last).length + ', minmax(110px, 1fr))', policyNote: capped ? 'Showing first 120 rows.' : '',
      addChoice: addChoice, addCombine: addCombine, addBucket: addBucket, addFloor: addFloor,
      loadCisa: () => this.setState({ config: this.cisa(), ans: {} }),
      loadBlank: () => this.setState({ config: this.blank(), ans: {} }),
      goQueue: () => this.setState({ tab: 'queue', ans: {} })
    };
  }


  previewVals() {
    const pvw = this.state.preview;
    const blank = { fileName: '', generator: '', generated: '', tiles: [], filters: '', sample: [], cta: '', replacePressed: 'false', trackStyle: '', knobStyle: '' };
    if (!pvw) return blank;
    const d = pvw.doc, it = pvw.items, f = d.filters || {};
    const existing = {}; this.allVulns().forEach((v) => { existing[v.id] = true; });
    const dup = it.filter((v) => existing[v.id]).length;
    const fl = [];
    if (f.kev_only) fl.push('KEV only'); if (f.min_epss != null) fl.push('EPSS ≥ ' + f.min_epss); if (f.min_cvss != null) fl.push('CVSS ≥ ' + f.min_cvss);
    if (f.start) fl.push('from ' + f.start.slice(0, 10)); if (f.limit) fl.push('top ' + f.limit);
    const gen = d.generated_at ? new Date(d.generated_at) : null;
    const rep = this.state.replaceSample;
    return {
      fileName: pvw.fileName, generator: d.generator || 'unknown generator',
      generated: gen && !isNaN(gen) ? gen.toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : 'no timestamp',
      tiles: [{ k: 'CVEs', v: String(it.length) }, { k: 'In KEV', v: String(it.filter((v) => v.kev).length) }, { k: 'Matched before limit', v: String(d.matched != null ? d.matched : it.length) }, { k: 'Already in queue', v: String(dup) }],
      filters: 'Export filters: ' + (fl.length ? fl.join(' · ') : 'none') + '. Ranked KEV first, then EPSS, then CVSS.',
      sample: it.slice(0, 30).map((v) => ({ id: v.id, title: v.title })),
      cta: 'Add ' + it.length + ' to queue',
      replacePressed: rep ? 'true' : 'false',
      trackStyle: rep ? 'background: #6EA8FF' : 'background: #2A3240',
      knobStyle: rep ? 'margin-left: 14px' : 'margin-left: 0'
    };
  }

  countPaths(cfg, bid) {
    const lists = cfg.steps.map((s) => this.vals(s));
    return this.cart(lists).filter((combo) => this.lookup(cfg, combo.map((x) => x.id).join('|')) === bid).length;
  }

  moveStep(i, j) {
    this.upd((c) => {
      const t = c.steps[i]; c.steps[i] = c.steps[j]; c.steps[j] = t;
      const nt = {}; Object.keys(c.table).forEach((k) => { const p = k.split('|'); const x = p[i]; p[i] = p[j]; p[j] = x; nt[p.join('|')] = c.table[k]; }); c.table = nt;
    });
    this.setState({ ans: {} });
  }

  removeStep(i) {
    this.upd((c) => {
      const sid = c.steps[i].id;
      c.steps.splice(i, 1);
      const nt = {}; Object.keys(c.table).forEach((k) => { const p = k.split('|'); p.splice(i, 1); const nk = p.join('|'); if (!(nk in nt)) nt[nk] = c.table[k]; }); c.table = nt;
      c.floors = c.floors.filter((f) => f.step !== sid);
    });
    this.setState({ ans: {} });
  }
}

VulnTriage.mount(Component, document.getElementById('app'), document.getElementById('app-template'));

// Offensive Security Tools tab
window.OffensiveTab = {
  subTab: 'recon',
  _results: {},

  render() {
    return `
      <div class="flex" style="height:calc(100vh - 56px)">
        <!-- Sub-tab sidebar -->
        <div class="w-40 shrink-0 bg-gray-900 border-r border-gray-800 py-3 overflow-y-auto">
          <div class="px-3 text-xs text-gray-500 uppercase mb-2">Reconnaissance</div>
          <button onclick="OffensiveTab.switchSub('recon')" class="off-sub-btn ${this.subTab==='recon'?'active':''}" data-sub="recon">Tech Fingerprint</button>
          <button onclick="OffensiveTab.switchSub('subdomains')" class="off-sub-btn ${this.subTab==='subdomains'?'active':''}" data-sub="subdomains">Subdomains</button>
          <button onclick="OffensiveTab.switchSub('discover')" class="off-sub-btn ${this.subTab==='discover'?'active':''}" data-sub="discover">Endpoint Discovery</button>
          <button onclick="OffensiveTab.switchSub('schema')" class="off-sub-btn ${this.subTab==='schema'?'active':''}" data-sub="schema">API Schema</button>

          <div class="px-3 text-xs text-gray-500 uppercase mb-2 mt-4">Tampering</div>
          <button onclick="OffensiveTab.switchSub('inject')" class="off-sub-btn ${this.subTab==='inject'?'active':''}" data-sub="inject">Injection Points</button>
          <button onclick="OffensiveTab.switchSub('tamper')" class="off-sub-btn ${this.subTab==='tamper'?'active':''}" data-sub="tamper">Auto Tamper</button>
          <button onclick="OffensiveTab.switchSub('payloads')" class="off-sub-btn ${this.subTab==='payloads'?'active':''}" data-sub="payloads">Payload Swapper</button>
          <button onclick="OffensiveTab.switchSub('massassign')" class="off-sub-btn ${this.subTab==='massassign'?'active':''}" data-sub="massassign">Mass Assignment</button>

          <div class="px-3 text-xs text-gray-500 uppercase mb-2 mt-4">Auth Testing</div>
          <button onclick="OffensiveTab.switchSub('authstrip')" class="off-sub-btn ${this.subTab==='authstrip'?'active':''}" data-sub="authstrip">Auth Stripper</button>
          <button onclick="OffensiveTab.switchSub('tokenanalyze')" class="off-sub-btn ${this.subTab==='tokenanalyze'?'active':''}" data-sub="tokenanalyze">Token Analyzer</button>
          <button onclick="OffensiveTab.switchSub('sessioncmp')" class="off-sub-btn ${this.subTab==='sessioncmp'?'active':''}" data-sub="sessioncmp">Session Compare</button>
          <button onclick="OffensiveTab.switchSub('privmatrix')" class="off-sub-btn ${this.subTab==='privmatrix'?'active':''}" data-sub="privmatrix">Privilege Matrix</button>

          <div class="px-3 text-xs text-gray-500 uppercase mb-2 mt-4">Scanner</div>
          <button onclick="OffensiveTab.switchSub('sensitive')" class="off-sub-btn ${this.subTab==='sensitive'?'active':''}" data-sub="sensitive">Sensitive Data</button>
          <button onclick="OffensiveTab.switchSub('headerscan')" class="off-sub-btn ${this.subTab==='headerscan'?'active':''}" data-sub="headerscan">Header Audit</button>
          <button onclick="OffensiveTab.switchSub('errors')" class="off-sub-btn ${this.subTab==='errors'?'active':''}" data-sub="errors">Error Analysis</button>

          <div class="px-3 text-xs text-gray-500 uppercase mb-2 mt-4">Exploit</div>
          <button onclick="OffensiveTab.switchSub('csrf')" class="off-sub-btn ${this.subTab==='csrf'?'active':''}" data-sub="csrf">CSRF PoC</button>
          <button onclick="OffensiveTab.switchSub('clickjack')" class="off-sub-btn ${this.subTab==='clickjack'?'active':''}" data-sub="clickjack">Clickjacking</button>
          <button onclick="OffensiveTab.switchSub('ssrf')" class="off-sub-btn ${this.subTab==='ssrf'?'active':''}" data-sub="ssrf">SSRF Probes</button>
          <button onclick="OffensiveTab.switchSub('wsfuzz')" class="off-sub-btn ${this.subTab==='wsfuzz'?'active':''}" data-sub="wsfuzz">WS Fuzzer</button>
          <button onclick="OffensiveTab.switchSub('race')" class="off-sub-btn ${this.subTab==='race'?'active':''}" data-sub="race">Race Condition</button>
        </div>
        <!-- Content -->
        <div class="flex-1 overflow-y-auto p-6" id="off-content">
          ${this._renderSubContent()}
        </div>
      </div>`;
  },

  switchSub(sub) {
    this.subTab = sub;
    document.querySelectorAll('.off-sub-btn').forEach(b => b.classList.remove('active'));
    const btn = document.querySelector(`.off-sub-btn[data-sub="${sub}"]`);
    if (btn) btn.classList.add('active');
    document.getElementById('off-content').innerHTML = this._renderSubContent();
  },

  _renderSubContent() {
    switch(this.subTab) {
      case 'recon': return this._renderRecon();
      case 'subdomains': return this._renderSubdomains();
      case 'discover': return this._renderDiscover();
      case 'schema': return this._renderSchema();
      case 'inject': return this._renderInject();
      case 'tamper': return this._renderTamper();
      case 'payloads': return this._renderPayloads();
      case 'massassign': return this._renderMassAssign();
      case 'authstrip': return this._renderAuthStrip();
      case 'tokenanalyze': return this._renderTokenAnalyze();
      case 'sessioncmp': return this._renderSessionCmp();
      case 'privmatrix': return this._renderPrivMatrix();
      case 'sensitive': return this._renderSensitive();
      case 'headerscan': return this._renderHeaderScan();
      case 'errors': return this._renderErrors();
      case 'csrf': return this._renderCSRF();
      case 'clickjack': return this._renderClickjack();
      case 'ssrf': return this._renderSSRF();
      case 'wsfuzz': return this._renderWSFuzz();
      case 'race': return this._renderRace();
      default: return '<div class="text-gray-500">Select a tool</div>';
    }
  },

  // ── Helpers ──────────────────────────────────────────────

  _card(title, content) {
    return `<div class="max-w-4xl"><h2 class="text-lg font-bold text-white mb-3">${title}</h2>${content}</div>`;
  },

  _input(id, label, placeholder, value) {
    return `<div><label class="text-xs text-gray-400 mb-1 block">${label}</label><input id="${id}" type="text" value="${esc(value||'')}" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500" placeholder="${placeholder}"></div>`;
  },

  _btn(onclick, label, cls) {
    return `<button onclick="${onclick}" class="text-xs ${cls||'bg-indigo-600 hover:bg-indigo-500'} text-white px-4 py-1.5 rounded font-bold">${label}</button>`;
  },

  _flowInput(id) {
    return this._input(id, 'Flow ID', 'Enter flow ID from traffic tab', window._offensivePrefill?.flowId || '');
  },

  _resultsDiv(id) {
    return `<div id="${id}" class="mt-4"></div>`;
  },

  async _post(url, body) {
    const resp = await authFetch(url, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if (!resp.ok) { const t = await resp.text(); throw new Error(t); }
    return resp.json();
  },

  async _get(url) {
    const resp = await authFetch(url);
    if (!resp.ok) { const t = await resp.text(); throw new Error(t); }
    return resp.json();
  },

  // ── Recon: Tech Fingerprint ──────────────────────────────

  _renderRecon() {
    return this._card('Technology Fingerprinter', `
      <p class="text-xs text-gray-400 mb-3">Analyze captured traffic to detect web technologies, frameworks, CDNs, and infrastructure per domain.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('recon-domain', 'Domain Filter (optional)', 'example.com', '')}
        ${this._btn("OffensiveTab.runRecon()", "Scan Traffic")}
      </div>
      ${this._resultsDiv('recon-results')}`);
  },

  async runRecon() {
    const el = document.getElementById('recon-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Scanning...</div>';
    try {
      const data = await this._post('/api/recon/fingerprint', {domain: document.getElementById('recon-domain').value});
      if (!data.count) { el.innerHTML = '<div class="text-xs text-gray-500">No technologies detected</div>'; return; }
      el.innerHTML = Object.entries(data.domains).map(([domain, cats]) => `
        <div class="bg-gray-900 rounded p-3 border border-gray-700 mb-2">
          <div class="text-sm font-bold text-white mb-2">${esc(domain)}</div>
          ${Object.entries(cats).map(([cat, techs]) => `
            <div class="mb-1"><span class="text-xs text-gray-500">${esc(cat)}:</span>
            ${techs.map(t => `<span class="text-xs bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded ml-1">${esc(t)}</span>`).join('')}</div>
          `).join('')}
        </div>
      `).join('');
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Recon: Subdomains ────────────────────────────────────

  _renderSubdomains() {
    return this._card('Subdomain Collector', `
      <p class="text-xs text-gray-400 mb-3">Passively collect subdomains from captured traffic (headers, cookies, CSP, redirects, response bodies).</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('sub-domain', 'Base Domain', 'example.com', '')}
        ${this._btn("OffensiveTab.runSubdomains()", "Collect")}
      </div>
      ${this._resultsDiv('sub-results')}`);
  },

  async runSubdomains() {
    const el = document.getElementById('sub-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Collecting...</div>';
    try {
      const domain = document.getElementById('sub-domain').value;
      const data = await this._get(`/api/recon/subdomains?domain=${encodeURIComponent(domain)}`);
      this._results.subdomains = data.subdomains;
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">Found ${data.count} domains</div>
        <div class="bg-gray-900 rounded p-3 border border-gray-700 max-h-96 overflow-y-auto">
        ${data.subdomains.map(s => `<div class="text-xs text-gray-300 py-0.5 font-mono">${esc(s)}</div>`).join('')}
        </div>
        <button onclick="OffensiveTab._copySubdomains()" class="text-xs text-indigo-400 mt-2">Copy All</button>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  _copySubdomains() {
    copyToClipboard((this._results.subdomains || []).join('\n'));
    Toast.show('Copied', 'success');
  },

  // ── Recon: Endpoint Discovery ────────────────────────────

  _renderDiscover() {
    return this._card('Hidden Endpoint Discovery', `
      <p class="text-xs text-gray-400 mb-3">Probe for hidden endpoints using common path wordlists.</p>
      <div class="grid grid-cols-2 gap-3 mb-3">
        ${this._input('disc-url', 'Base URL', 'https://example.com/', '')}
        ${this._input('disc-max', 'Max Probes', '50', '50')}
      </div>
      <div class="mb-3">${this._btn("OffensiveTab.runDiscover()", "Discover", "bg-red-600 hover:bg-red-500")}</div>
      ${this._resultsDiv('disc-results')}`);
  },

  async runDiscover() {
    const el = document.getElementById('disc-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Probing endpoints...</div>';
    try {
      const data = await this._post('/api/recon/discover', {
        base_url: document.getElementById('disc-url').value,
        max_probes: parseInt(document.getElementById('disc-max').value) || 50,
      });
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.found} interesting / ${data.total} total</div>
        <div class="space-y-1 max-h-96 overflow-y-auto">
        ${data.results.map(r => `
          <div class="flex items-center gap-2 text-xs py-1 ${r.interesting ? 'bg-green-900/20 px-2 rounded' : ''}">
            <span class="w-10 ${this._statusColor(r.status_code)} font-bold">${r.status_code||'ERR'}</span>
            <span class="flex-1 font-mono text-gray-300">${esc(r.path)}</span>
            <span class="text-gray-500">${r.size}B</span>
            ${r.redirect ? `<span class="text-blue-400">→ ${esc(r.redirect)}</span>` : ''}
          </div>
        `).join('')}</div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Recon: API Schema ────────────────────────────────────

  _renderSchema() {
    return this._card('API Schema Reconstructor', `
      <p class="text-xs text-gray-400 mb-3">Auto-build API schema from observed traffic patterns.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('schema-domain', 'Domain Filter (optional)', 'api.example.com', '')}
        ${this._btn("OffensiveTab.runSchema()", "Build Schema")}
      </div>
      ${this._resultsDiv('schema-results')}`);
  },

  async runSchema() {
    const el = document.getElementById('schema-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Building schema...</div>';
    try {
      const data = await this._get(`/api/recon/schema?domain=${encodeURIComponent(document.getElementById('schema-domain').value)}`);
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.count} endpoints found</div>
        <div class="space-y-2 max-h-[500px] overflow-y-auto">
        ${data.endpoints.map(ep => `
          <div class="bg-gray-900 rounded p-3 border border-gray-700">
            <div class="text-xs font-bold text-white mb-1">${esc(ep.host)} <span class="text-indigo-400">${esc(ep.path)}</span></div>
            <div class="flex gap-1 mb-1">
              ${Object.entries(ep.methods).map(([m, info]) => `
                <span class="text-xs px-2 py-0.5 rounded ${this._methodColor(m)}">${esc(m)} <span class="text-gray-400">(${info.count}x)</span></span>
              `).join('')}
            </div>
            ${Object.entries(ep.methods).map(([m, info]) => `
              <div class="text-xs text-gray-500">
                ${info.query_params.length ? `Params: ${info.query_params.map(p => '<code class="text-yellow-300">'+esc(p)+'</code>').join(', ')}` : ''}
                ${Object.entries(info.status_codes).map(([s,c]) => `<span class="${this._statusColor(parseInt(s))}">${s}</span>:${c}`).join(' ')}
              </div>
            `).join('')}
          </div>
        `).join('')}</div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Tamper: Injection Points ─────────────────────────────

  _renderInject() {
    return this._card('Injection Point Mapper', `
      <p class="text-xs text-gray-400 mb-3">Identify all injectable parameters in a request (URL, query, headers, cookies, body).</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._flowInput('inject-flow')}
        ${this._btn("OffensiveTab.runInject()", "Map Points")}
      </div>
      ${this._resultsDiv('inject-results')}`);
  },

  async runInject() {
    const el = document.getElementById('inject-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Mapping...</div>';
    try {
      const data = await this._post('/api/tamper/injection-points', {flow_id: document.getElementById('inject-flow').value});
      this._results.injectionPoints = data.points;
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.count} injection points in ${data.request.method} ${esc(data.request.url||'')}</div>
        <table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Type</th><th class="text-left py-1 px-2">Name</th><th class="text-left py-1 px-2">Value</th><th class="text-left py-1 px-2">Location</th>
        </tr></thead><tbody>
        ${data.points.map(p => `<tr class="border-b border-gray-800 hover:bg-gray-800/50">
          <td class="py-1 px-2"><span class="px-1.5 py-0.5 rounded ${this._typeColor(p.type)}">${esc(p.type)}</span></td>
          <td class="py-1 px-2 font-mono text-indigo-300">${esc(p.name)}</td>
          <td class="py-1 px-2 font-mono text-gray-300 max-w-xs truncate">${esc(String(p.value).substring(0,80))}</td>
          <td class="py-1 px-2 text-gray-500">${esc(p.location)}</td>
        </tr>`).join('')}
        </tbody></table>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Tamper: Auto Tamper ──────────────────────────────────

  _renderTamper() {
    return this._card('Auto Parameter Tamper', `
      <p class="text-xs text-gray-400 mb-3">Auto-generate tampered variants: IDOR, type juggling, SQLi, XSS, path traversal, command injection, SSTI.</p>
      <div class="grid grid-cols-2 gap-3 mb-3">
        ${this._flowInput('tamper-flow')}
        ${this._input('tamper-max', 'Max Requests', '50', '50')}
      </div>
      <div class="flex flex-wrap gap-2 mb-3 text-xs">
        ${['idor','type_juggle','boundary','sqli','xss','path_traversal','cmd_inject','ssti'].map(s =>
          `<label class="flex items-center gap-1 text-gray-300"><input type="checkbox" value="${s}" class="tamper-strat accent-indigo-500" ${['idor','type_juggle','boundary'].includes(s)?'checked':''}>${s.replace(/_/g,' ')}</label>`
        ).join('')}
      </div>
      <div class="flex gap-2 mb-3">
        ${this._btn("OffensiveTab.runTamper(false)", "Preview Variants")}
        ${this._btn("OffensiveTab.runTamper(true)", "Fire All", "bg-red-600 hover:bg-red-500")}
      </div>
      ${this._resultsDiv('tamper-results')}`);
  },

  async runTamper(fire) {
    const el = document.getElementById('tamper-results');
    el.innerHTML = '<div class="text-xs text-gray-500">' + (fire ? 'Firing...' : 'Generating...') + '</div>';
    try {
      const strategies = [...document.querySelectorAll('.tamper-strat:checked')].map(c => c.value);
      const data = await this._post('/api/tamper/auto', {
        flow_id: document.getElementById('tamper-flow').value,
        strategies: strategies,
        fire: fire,
        max_requests: parseInt(document.getElementById('tamper-max').value) || 50,
      });
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.total} variants ${data.fired ? '(fired)' : '(preview)'}</div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Strategy</th><th class="text-left py-1 px-2">Point</th><th class="text-left py-1 px-2">Payload</th>
          ${data.fired ? '<th class="py-1 px-2">Status</th><th class="py-1 px-2">Size</th><th class="py-1 px-2">Time</th>' : ''}
        </tr></thead><tbody>
        ${data.results.map(r => `<tr class="border-b border-gray-800 ${r.response_status && r.response_status !== r.status_code ? 'bg-yellow-900/10' : ''}">
          <td class="py-1 px-2 text-gray-400">${esc(r.strategy||'')}</td>
          <td class="py-1 px-2 text-indigo-300 font-mono">${esc(r.point_name||'')}</td>
          <td class="py-1 px-2 font-mono text-gray-300 max-w-xs truncate">${esc(String(r.payload||'').substring(0,60))}</td>
          ${data.fired ? `
            <td class="py-1 px-2 text-center ${this._statusColor(r.response_status)}">${r.response_status||'ERR'}</td>
            <td class="py-1 px-2 text-center text-gray-400">${r.response_size||0}</td>
            <td class="py-1 px-2 text-center text-gray-400">${r.response_duration||0}ms</td>
          ` : ''}
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Tamper: Payload Swapper ──────────────────────────────

  _renderPayloads() {
    return this._card('Payload Swapper', `
      <p class="text-xs text-gray-400 mb-3">Fire a payload list at a specific injection point and detect anomalies.</p>
      <div class="grid grid-cols-3 gap-3 mb-3">
        ${this._flowInput('payload-flow')}
        ${this._input('payload-point', 'Injection Point Name', 'e.g. id, username', '')}
        <div><label class="text-xs text-gray-400 mb-1 block">Payload Type</label>
          <select id="payload-type" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700">
            <option value="xss">XSS</option><option value="sqli">SQLi</option><option value="ssti">SSTI</option>
            <option value="path_traversal">Path Traversal</option><option value="cmd_inject">Command Injection</option>
          </select>
        </div>
      </div>
      <div class="mb-3">${this._btn("OffensiveTab.runPayloads()", "Fire Payloads", "bg-red-600 hover:bg-red-500")}</div>
      ${this._resultsDiv('payload-results')}`);
  },

  async runPayloads() {
    const el = document.getElementById('payload-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Firing payloads...</div>';
    try {
      const data = await this._post('/api/tamper/payloads', {
        flow_id: document.getElementById('payload-flow').value,
        point_name: document.getElementById('payload-point').value,
        payload_type: document.getElementById('payload-type').value,
      });
      const baseInfo = `Baseline: ${data.baseline.status_code} / ${data.baseline.size}B / ${data.baseline.duration_ms}ms`;
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${baseInfo} | ${data.found} interesting / ${data.total}</div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Payload</th><th class="py-1 px-2">Status</th><th class="py-1 px-2">Size</th><th class="py-1 px-2">Time</th><th class="text-left py-1 px-2">Anomalies</th>
        </tr></thead><tbody>
        ${data.results.map(r => `<tr class="border-b border-gray-800 ${r.interesting ? 'bg-red-900/15' : ''}">
          <td class="py-1 px-2 font-mono text-gray-300 max-w-xs truncate">${esc(r.payload.substring(0,60))}</td>
          <td class="py-1 px-2 text-center ${this._statusColor(r.status_code)}">${r.status_code||'ERR'}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.size}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.duration_ms}ms</td>
          <td class="py-1 px-2 text-yellow-300">${(r.anomalies||[]).join('; ')}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Tamper: Mass Assignment ──────────────────────────────

  _renderMassAssign() {
    return this._card('Mass Assignment Tester', `
      <p class="text-xs text-gray-400 mb-3">Add hidden fields (is_admin, role, price, etc.) to JSON requests and test acceptance.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._flowInput('mass-flow')}
        ${this._btn("OffensiveTab.runMassAssign()", "Test Mass Assignment", "bg-red-600 hover:bg-red-500")}
      </div>
      ${this._resultsDiv('mass-results')}`);
  },

  async runMassAssign() {
    const el = document.getElementById('mass-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Testing fields...</div>';
    try {
      const data = await this._post('/api/tamper/mass-assign', {flow_id: document.getElementById('mass-flow').value});
      if (data.error) { el.innerHTML = `<div class="text-xs text-yellow-400">${esc(data.error)}</div>`; return; }
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">Baseline: ${data.baseline.status_code} / ${data.baseline.size}B | ${data.found} interesting / ${data.total}</div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Field</th><th class="text-left py-1 px-2">Value</th><th class="py-1 px-2">Status</th><th class="py-1 px-2">Size</th><th class="text-left py-1 px-2">Findings</th>
        </tr></thead><tbody>
        ${data.results.map(r => `<tr class="border-b border-gray-800 ${r.interesting ? 'bg-red-900/15' : ''}">
          <td class="py-1 px-2 font-mono text-indigo-300">${esc(r.field)}</td>
          <td class="py-1 px-2 font-mono text-gray-300">${esc(String(r.value).substring(0,30))}</td>
          <td class="py-1 px-2 text-center ${this._statusColor(r.status_code)}">${r.status_code||'ERR'}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.size}</td>
          <td class="py-1 px-2 text-yellow-300 text-xs">${(r.anomalies||[]).join('; ')}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Auth: Strip ──────────────────────────────────────────

  _renderAuthStrip() {
    return this._card('Auth Stripper', `
      <p class="text-xs text-gray-400 mb-3">Strip authentication (Bearer, cookies, API keys) and replay to test for broken auth.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._flowInput('strip-flow')}
        ${this._btn("OffensiveTab.runAuthStrip()", "Strip & Test", "bg-red-600 hover:bg-red-500")}
      </div>
      ${this._resultsDiv('strip-results')}`);
  },

  async runAuthStrip() {
    const el = document.getElementById('strip-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Stripping auth...</div>';
    try {
      const data = await this._post('/api/auth-test/strip', {flow_id: document.getElementById('strip-flow').value});
      el.innerHTML = `
        <div class="text-xs text-gray-400 mb-2">Baseline: ${data.baseline.status_code} / ${data.baseline.size}B</div>
        ${data.any_vulnerable ? '<div class="bg-red-900/30 text-red-300 text-xs px-3 py-2 rounded mb-2 font-bold">Potential Broken Authentication Detected!</div>' : ''}
        <div class="space-y-2">
        ${data.results.map(r => `
          <div class="bg-gray-900 rounded p-3 border ${r.vulnerable ? 'border-red-700' : 'border-gray-700'}">
            <div class="flex items-center justify-between">
              <div><span class="text-sm font-bold ${r.vulnerable ? 'text-red-400' : 'text-white'}">${esc(r.variant)}</span>
              <span class="text-xs text-gray-500 ml-2">${esc(r.desc)}</span></div>
              <span class="${this._statusColor(r.status_code)} font-bold">${r.status_code||'ERR'}</span>
            </div>
            ${r.notes.length ? `<div class="text-xs text-yellow-300 mt-1">${r.notes.join(' | ')}</div>` : ''}
          </div>
        `).join('')}</div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Auth: Token Analyzer ─────────────────────────────────

  _renderTokenAnalyze() {
    return this._card('Token Analyzer', `
      <p class="text-xs text-gray-400 mb-3">Analyze JWT tokens, API keys, session tokens for security issues.</p>
      <div class="mb-3">
        <label class="text-xs text-gray-400 mb-1 block">Token</label>
        <textarea id="token-input" rows="3" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono resize-none focus:outline-none focus:border-indigo-500" placeholder="Paste token here (JWT, Bearer, API key, etc.)"></textarea>
      </div>
      ${this._btn("OffensiveTab.runTokenAnalyze()", "Analyze")}
      ${this._resultsDiv('token-results')}`);
  },

  async runTokenAnalyze() {
    const el = document.getElementById('token-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Analyzing...</div>';
    try {
      const data = await this._post('/api/auth-test/token-analyze', {token: document.getElementById('token-input').value});
      el.innerHTML = `
        <div class="bg-gray-900 rounded p-4 border border-gray-700">
          <div class="flex items-center gap-3 mb-3">
            <span class="text-sm font-bold text-white">${esc(data.type)}</span>
            <span class="text-xs text-gray-400">${data.raw_length} chars</span>
            <span class="text-xs text-gray-400">Entropy: ${data.entropy}</span>
          </div>
          ${data.issues.length ? `<div class="mb-3">${data.issues.map(i => `
            <div class="text-xs px-2 py-1 rounded mb-1 ${this._severityBg(i.severity)}">${esc(i.severity.toUpperCase())}: ${esc(i.desc)}</div>
          `).join('')}</div>` : ''}
          <div class="text-xs text-gray-400 space-y-1">${data.analysis.map(a => `<div>• ${esc(a)}</div>`).join('')}</div>
          ${data.jwt_header ? `<details class="mt-3"><summary class="text-xs text-indigo-400 cursor-pointer">JWT Header</summary><pre class="text-xs text-gray-300 bg-gray-950 rounded p-2 mt-1">${esc(JSON.stringify(data.jwt_header,null,2))}</pre></details>` : ''}
          ${data.jwt_payload ? `<details class="mt-2"><summary class="text-xs text-indigo-400 cursor-pointer">JWT Payload</summary><pre class="text-xs text-gray-300 bg-gray-950 rounded p-2 mt-1">${esc(JSON.stringify(data.jwt_payload,null,2))}</pre></details>` : ''}
        </div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Auth: Session Compare ────────────────────────────────

  _renderSessionCmp() {
    return this._card('Session Comparer', `
      <p class="text-xs text-gray-400 mb-3">Replay a request with different session tokens and auto-diff responses to find IDOR/privilege escalation.</p>
      <div class="mb-3">${this._flowInput('cmp-flow')}</div>
      <div id="cmp-sessions">
        <div class="text-xs text-gray-500 mb-2">Sessions (min 2):</div>
        <div class="space-y-2" id="cmp-session-list">
          <div class="flex gap-2"><input class="cmp-name flex-none w-24 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Name" value="User A">
          <input class="cmp-header flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="Authorization: Bearer token_a"></div>
          <div class="flex gap-2"><input class="cmp-name flex-none w-24 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Name" value="User B">
          <input class="cmp-header flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="Authorization: Bearer token_b"></div>
        </div>
        <button onclick="OffensiveTab._addSession()" class="text-xs text-indigo-400 mt-1">+ Add Session</button>
      </div>
      <div class="mt-3">${this._btn("OffensiveTab.runSessionCmp()", "Compare", "bg-red-600 hover:bg-red-500")}</div>
      ${this._resultsDiv('cmp-results')}`);
  },

  _addSession() {
    const list = document.getElementById('cmp-session-list');
    const div = document.createElement('div');
    div.className = 'flex gap-2';
    div.innerHTML = `<input class="cmp-name flex-none w-24 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Name">
      <input class="cmp-header flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="Authorization: Bearer token">`;
    list.appendChild(div);
  },

  async runSessionCmp() {
    const el = document.getElementById('cmp-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Comparing sessions...</div>';
    try {
      const names = document.querySelectorAll('.cmp-name');
      const hdrs = document.querySelectorAll('.cmp-header');
      const sessions = [];
      names.forEach((n, i) => {
        const hdr = hdrs[i].value.trim();
        if (n.value && hdr) {
          const [key, ...rest] = hdr.split(':');
          sessions.push({name: n.value, headers: {[key.trim()]: rest.join(':').trim()}});
        }
      });
      const data = await this._post('/api/auth-test/compare', {
        flow_id: document.getElementById('cmp-flow').value, sessions
      });
      el.innerHTML = `<div class="space-y-2">
        ${data.results.map(r => `
          <div class="bg-gray-900 rounded p-3 border border-gray-700">
            <div class="flex items-center justify-between">
              <span class="text-sm font-bold text-white">${esc(r.name)}</span>
              <span class="${this._statusColor(r.status_code)} font-bold">${r.status_code} <span class="text-gray-500 font-normal">${r.size}B</span></span>
            </div>
          </div>
        `).join('')}
        ${data.diffs.map(d => `
          <div class="text-xs bg-gray-800 rounded p-2 ${!d.body_match ? 'border border-yellow-700' : ''}">
            ${esc(d.compared)}: Status ${d.status_match ? 'match' : 'DIFFER'} | Body ${d.body_match ? 'match' : 'DIFFER ('+d.lines_changed+' lines)'} | Size diff: ${d.size_diff}B
          </div>
        `).join('')}
      </div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Auth: Privilege Matrix ───────────────────────────────

  _renderPrivMatrix() {
    return this._card('Privilege Matrix Builder', `
      <p class="text-xs text-gray-400 mb-3">Build access control matrix: test multiple endpoints with multiple roles.</p>
      <div class="grid grid-cols-2 gap-4 mb-3">
        <div>
          <div class="text-xs text-gray-500 mb-2">Roles:</div>
          <div class="space-y-1" id="priv-roles">
            <div class="flex gap-1"><input class="priv-role-name w-20 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Role" value="Admin">
            <input class="priv-role-hdr flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="Authorization: Bearer admin_token"></div>
            <div class="flex gap-1"><input class="priv-role-name w-20 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Role" value="User">
            <input class="priv-role-hdr flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="Authorization: Bearer user_token"></div>
            <div class="flex gap-1"><input class="priv-role-name w-20 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700" placeholder="Role" value="Guest">
            <input class="priv-role-hdr flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono" placeholder="(empty for unauthenticated)"></div>
          </div>
        </div>
        <div>
          <div class="text-xs text-gray-500 mb-2">Flow IDs (one per line):</div>
          <textarea id="priv-flows" rows="4" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono resize-none" placeholder="flow-id-1\nflow-id-2"></textarea>
        </div>
      </div>
      ${this._btn("OffensiveTab.runPrivMatrix()", "Build Matrix", "bg-red-600 hover:bg-red-500")}
      ${this._resultsDiv('priv-results')}`);
  },

  async runPrivMatrix() {
    const el = document.getElementById('priv-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Building matrix...</div>';
    try {
      const roleNames = document.querySelectorAll('.priv-role-name');
      const roleHdrs = document.querySelectorAll('.priv-role-hdr');
      const roles = [];
      roleNames.forEach((n, i) => {
        if (n.value) {
          const hdr = roleHdrs[i].value.trim();
          const headers = {};
          if (hdr) { const [k,...v] = hdr.split(':'); headers[k.trim()] = v.join(':').trim(); }
          roles.push({name: n.value, headers});
        }
      });
      const flowIds = document.getElementById('priv-flows').value.split('\n').map(s=>s.trim()).filter(Boolean);
      const data = await this._post('/api/auth-test/priv-matrix', {roles, flow_ids: flowIds});

      const roleList = roles.map(r => r.name);
      el.innerHTML = `
        ${data.issues.length ? data.issues.map(i => `<div class="text-xs bg-yellow-900/30 text-yellow-300 px-2 py-1 rounded mb-1">${esc(i.issue)} — ${esc(i.endpoint)}</div>`).join('') : ''}
        <table class="w-full text-xs mt-2"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Endpoint</th>
          ${roleList.map(r => `<th class="py-1 px-2">${esc(r)}</th>`).join('')}
        </tr></thead><tbody>
        ${data.matrix.map(row => `<tr class="border-b border-gray-800">
          <td class="py-1 px-2 font-mono text-gray-300">${esc(row.endpoint)}</td>
          ${roleList.map(r => {
            const info = row.roles[r] || {};
            const cls = info.access === 'granted' ? 'text-green-400' : info.access === 'denied' ? 'text-red-400' : 'text-gray-500';
            return `<td class="py-1 px-2 text-center ${cls}">${info.status_code||'?'}</td>`;
          }).join('')}
        </tr>`).join('')}
        </tbody></table>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Scanner: Sensitive Data ──────────────────────────────

  _renderSensitive() {
    return this._card('Sensitive Data Scanner', `
      <p class="text-xs text-gray-400 mb-3">Scan captured traffic for API keys, tokens, passwords, PII, stack traces, and more.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('sens-flow', 'Flow ID (optional, empty=scan all)', '', '')}
        ${this._btn("OffensiveTab.runSensitive()", "Scan")}
      </div>
      ${this._resultsDiv('sens-results')}`);
  },

  async runSensitive() {
    const el = document.getElementById('sens-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Scanning traffic...</div>';
    try {
      const fid = document.getElementById('sens-flow').value;
      const data = await this._post('/api/scanner/sensitive', fid ? {flow_id: fid} : {});
      const sevColors = {critical:'text-red-400',high:'text-orange-400',medium:'text-yellow-400',low:'text-blue-400',info:'text-gray-400'};
      el.innerHTML = `
        <div class="flex gap-3 mb-3 text-xs">
          ${Object.entries(data.by_severity||{}).map(([sev,cnt]) => `<span class="${sevColors[sev]||'text-gray-400'} font-bold">${sev}: ${cnt}</span>`).join('')}
          <span class="text-gray-500">Total: ${data.total}</span>
        </div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Severity</th><th class="text-left py-1 px-2">Pattern</th><th class="text-left py-1 px-2">Match</th><th class="text-left py-1 px-2">Location</th><th class="text-left py-1 px-2">Host</th>
        </tr></thead><tbody>
        ${(data.findings||[]).map(f => `<tr class="border-b border-gray-800">
          <td class="py-1 px-2 ${sevColors[f.severity]||''} font-bold">${esc(f.severity)}</td>
          <td class="py-1 px-2 text-gray-300">${esc(f.pattern_name)}</td>
          <td class="py-1 px-2 font-mono text-gray-400">${esc(f.matched)}</td>
          <td class="py-1 px-2 text-gray-500">${esc(f.location)}</td>
          <td class="py-1 px-2 text-gray-500">${esc(f.host)}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Scanner: Header Audit ────────────────────────────────

  _renderHeaderScan() {
    return this._card('Security Header Auditor', `
      <p class="text-xs text-gray-400 mb-3">Grade response security headers per domain (HSTS, CSP, X-Frame-Options, cookies, etc.).</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('hdrscan-domain', 'Domain (optional)', 'example.com', '')}
        ${this._btn("OffensiveTab.runHeaderScan()", "Audit")}
      </div>
      ${this._resultsDiv('hdrscan-results')}`);
  },

  async runHeaderScan() {
    const el = document.getElementById('hdrscan-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Auditing headers...</div>';
    try {
      const data = await this._post('/api/scanner/headers', {domain: document.getElementById('hdrscan-domain').value});
      el.innerHTML = `<div class="space-y-3">
        ${data.domains.map(d => `
          <div class="bg-gray-900 rounded p-4 border border-gray-700">
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-bold text-white">${esc(d.domain)}</span>
              <span class="text-lg font-bold ${d.grade==='A'?'text-green-400':d.grade==='B'?'text-blue-400':d.grade==='C'?'text-yellow-400':'text-red-400'}">${d.grade} <span class="text-xs text-gray-500">(${d.score}/${d.max_score})</span></span>
            </div>
            ${d.missing_headers.length ? `<div class="mb-2"><div class="text-xs text-red-400 mb-1">Missing:</div>
              ${d.missing_headers.map(h => `<div class="text-xs text-gray-400 ml-2">• <span class="text-red-300">${esc(h.name)}</span> <span class="text-gray-600">${esc(h.desc)}</span></div>`).join('')}
            </div>` : ''}
            ${d.present_headers.length ? `<div class="mb-2"><div class="text-xs text-green-400 mb-1">Present:</div>
              ${d.present_headers.map(h => `<div class="text-xs text-gray-400 ml-2">• <span class="text-green-300">${esc(h.name)}</span></div>`).join('')}
            </div>` : ''}
            ${(d.cookie_issues||[]).length ? `<div><div class="text-xs text-yellow-400 mb-1">Cookie Issues:</div>
              ${d.cookie_issues.map(c => `<div class="text-xs text-gray-400 ml-2">• ${esc(c.cookie)}: missing ${c.missing_flags.join(', ')}</div>`).join('')}
            </div>` : ''}
            ${(d.info_disclosure||[]).length ? `<div class="mt-1"><div class="text-xs text-orange-400 mb-1">Info Disclosure:</div>
              ${d.info_disclosure.map(i => `<div class="text-xs text-gray-400 ml-2">• ${esc(i.header)}: ${esc(i.value)}</div>`).join('')}
            </div>` : ''}
          </div>
        `).join('')}</div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Scanner: Error Analysis ──────────────────────────────

  _renderErrors() {
    return this._card('Error Fingerprinter', `
      <p class="text-xs text-gray-400 mb-3">Analyze 4xx/5xx error responses for info leakage: stack traces, file paths, debug pages, versions.</p>
      ${this._btn("OffensiveTab.runErrors()", "Analyze Errors")}
      ${this._resultsDiv('error-results')}`);
  },

  async runErrors() {
    const el = document.getElementById('error-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Analyzing errors...</div>';
    try {
      const data = await this._get('/api/scanner/errors');
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.total} error responses found</div>
        ${data.clusters.length ? `<div class="mb-3"><div class="text-xs text-gray-500 mb-1">Clusters:</div>
          ${data.clusters.map(c => `<div class="text-xs bg-gray-900 rounded p-2 mb-1 border border-gray-700">
            <span class="${this._statusColor(c.status_code)} font-bold">${c.status_code}</span>
            <span class="text-white">${esc(c.host)}</span>
            <span class="text-gray-400">(${c.count}x)</span>
            ${c.technologies.length ? c.technologies.map(t => `<span class="bg-red-900 text-red-300 px-1.5 py-0.5 rounded ml-1">${esc(t)}</span>`).join('') : ''}
          </div>`).join('')}
        </div>` : ''}
        <div class="max-h-[300px] overflow-y-auto space-y-1">
        ${(data.errors||[]).slice(0,50).map(e => `
          <div class="text-xs bg-gray-900 rounded p-2 border border-gray-800">
            <span class="${this._statusColor(e.status_code)} font-bold">${e.status_code}</span>
            <span class="text-gray-300">${esc(e.method)} ${esc(e.host)}${esc(e.path)}</span>
            ${e.detected.map(d => `<span class="bg-orange-900 text-orange-300 px-1 py-0.5 rounded text-xs ml-1">${esc(d.tech)}</span>`).join('')}
          </div>
        `).join('')}</div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Exploit: CSRF PoC ────────────────────────────────────

  _renderCSRF() {
    return this._card('CSRF PoC Generator', `
      <p class="text-xs text-gray-400 mb-3">Generate HTML proof-of-concept for CSRF attacks from captured requests.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._flowInput('csrf-flow')}
        ${this._btn("OffensiveTab.runCSRF()", "Generate PoC")}
      </div>
      ${this._resultsDiv('csrf-results')}`);
  },

  async runCSRF() {
    const el = document.getElementById('csrf-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Generating...</div>';
    try {
      const data = await this._post('/api/exploit/csrf-poc', {flow_id: document.getElementById('csrf-flow').value});
      el.innerHTML = `
        <div class="flex gap-2 mb-2">
          <button onclick="copyToClipboard(document.getElementById('csrf-html').textContent);Toast.show('Copied','success')" class="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded">Copy HTML</button>
          <button onclick="OffensiveTab._openPocWindow('csrf-html')" class="text-xs bg-red-600 hover:bg-red-500 text-white px-3 py-1 rounded">Open in New Tab</button>
        </div>
        <pre id="csrf-html" class="bg-gray-950 rounded p-3 text-xs text-gray-300 overflow-x-auto max-h-96">${esc(data.html)}</pre>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  _openPocWindow(elId) {
    const html = document.getElementById(elId).textContent;
    const w = window.open('', '_blank');
    w.document.write(html);
    w.document.close();
  },

  // ── Exploit: Clickjacking ────────────────────────────────

  _renderClickjack() {
    return this._card('Clickjacking PoC', `
      <p class="text-xs text-gray-400 mb-3">Check X-Frame-Options / CSP frame-ancestors and generate clickjacking PoC.</p>
      <div class="flex gap-3 items-end mb-3">
        ${this._input('click-url', 'Target URL', 'https://example.com/dashboard', '')}
        ${this._btn("OffensiveTab.runClickjack()", "Check & Generate")}
      </div>
      ${this._resultsDiv('click-results')}`);
  },

  async runClickjack() {
    const el = document.getElementById('click-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Checking...</div>';
    try {
      const data = await this._post('/api/exploit/clickjack', {url: document.getElementById('click-url').value});
      el.innerHTML = `
        <div class="mb-3 text-xs ${data.vulnerable ? 'bg-red-900/30 text-red-300' : 'bg-green-900/30 text-green-300'} px-3 py-2 rounded font-bold">
          ${data.vulnerable ? 'VULNERABLE — No framing protection' : 'PROTECTED — ' + data.protected_by.join(', ')}
        </div>
        <div class="flex gap-2 mb-2">
          <button onclick="copyToClipboard(document.getElementById('click-html').textContent);Toast.show('Copied','success')" class="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded">Copy HTML</button>
          <button onclick="OffensiveTab._openPocWindow('click-html')" class="text-xs bg-red-600 hover:bg-red-500 text-white px-3 py-1 rounded">Open in New Tab</button>
        </div>
        <pre id="click-html" class="bg-gray-950 rounded p-3 text-xs text-gray-300 overflow-x-auto max-h-96">${esc(data.html)}</pre>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Exploit: SSRF Probes ─────────────────────────────────

  _renderSSRF() {
    return this._card('SSRF Probe Generator', `
      <p class="text-xs text-gray-400 mb-3">Generate SSRF payloads for URL parameters: localhost, cloud metadata, internal services, protocol smuggling.</p>
      <div class="grid grid-cols-2 gap-3 mb-3">
        ${this._flowInput('ssrf-flow')}
        ${this._input('ssrf-param', 'URL Parameter Name', 'url, redirect, callback, etc.', '')}
      </div>
      <div class="flex flex-wrap gap-2 mb-3 text-xs">
        ${['localhost','cloud_metadata','internal_services','protocol_smuggling','bypass_filters'].map(c =>
          `<label class="flex items-center gap-1 text-gray-300"><input type="checkbox" value="${c}" class="ssrf-cat accent-indigo-500" ${['localhost','cloud_metadata'].includes(c)?'checked':''}>${c.replace(/_/g,' ')}</label>`
        ).join('')}
      </div>
      <div class="flex gap-2 mb-3">
        ${this._btn("OffensiveTab.runSSRF(false)", "Generate Payloads")}
        ${this._btn("OffensiveTab.runSSRF(true)", "Fire Payloads", "bg-red-600 hover:bg-red-500")}
      </div>
      ${this._resultsDiv('ssrf-results')}`);
  },

  async runSSRF(fire) {
    const el = document.getElementById('ssrf-results');
    el.innerHTML = '<div class="text-xs text-gray-500">' + (fire?'Firing...':'Generating...') + '</div>';
    try {
      const cats = [...document.querySelectorAll('.ssrf-cat:checked')].map(c => c.value);
      const data = await this._post('/api/exploit/ssrf', {
        flow_id: document.getElementById('ssrf-flow').value,
        param_name: document.getElementById('ssrf-param').value,
        categories: cats, fire
      });
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">${data.total} payloads${data.interesting?.length ? ` (${data.interesting.length} interesting)` : ''}</div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="text-left py-1 px-2">Category</th><th class="text-left py-1 px-2">Payload</th>
          ${fire ? '<th class="py-1 px-2">Status</th><th class="py-1 px-2">Size</th>' : ''}
        </tr></thead><tbody>
        ${data.payloads.map(r => `<tr class="border-b border-gray-800 ${r.interesting ? 'bg-red-900/15' : ''}">
          <td class="py-1 px-2 text-gray-400">${esc(r.category)}</td>
          <td class="py-1 px-2 font-mono text-gray-300">${esc(r.payload)}</td>
          ${fire ? `<td class="py-1 px-2 text-center ${this._statusColor(r.status_code)}">${r.status_code||'ERR'}</td><td class="py-1 px-2 text-center text-gray-400">${r.size||0}</td>` : ''}
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Exploit: WS Fuzzer ───────────────────────────────────

  _renderWSFuzz() {
    return this._card('WebSocket Fuzzer', `
      <p class="text-xs text-gray-400 mb-3">Fuzz active WebSocket connections with injection payloads, oversized frames, and malformed data.</p>
      <div class="grid grid-cols-2 gap-3 mb-3">
        ${this._flowInput('wsfuzz-flow')}
        ${this._input('wsfuzz-delay', 'Delay between messages (ms)', '100', '100')}
      </div>
      <div class="mb-3">${this._btn("OffensiveTab.runWSFuzz()", "Fuzz WebSocket", "bg-red-600 hover:bg-red-500")}</div>
      ${this._resultsDiv('wsfuzz-results')}`);
  },

  async runWSFuzz() {
    const el = document.getElementById('wsfuzz-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Fuzzing...</div>';
    try {
      const data = await this._post('/api/exploit/ws-fuzz', {
        flow_id: document.getElementById('wsfuzz-flow').value,
        delay_ms: parseInt(document.getElementById('wsfuzz-delay').value) || 100,
      });
      el.innerHTML = `<div class="text-xs text-gray-400 mb-2">Sent: ${data.sent} / Failed: ${data.failed}</div>
        <div class="max-h-[400px] overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="py-1 px-2">#</th><th class="text-left py-1 px-2">Payload</th><th class="py-1 px-2">Length</th><th class="py-1 px-2">Sent</th>
        </tr></thead><tbody>
        ${data.results.map(r => `<tr class="border-b border-gray-800">
          <td class="py-1 px-2 text-center text-gray-500">${r.index}</td>
          <td class="py-1 px-2 font-mono text-gray-300 max-w-sm truncate">${esc(r.payload)}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.payload_len}</td>
          <td class="py-1 px-2 text-center ${r.sent ? 'text-green-400' : 'text-red-400'}">${r.sent ? 'OK' : 'FAIL'}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Exploit: Race Condition ──────────────────────────────

  _renderRace() {
    return this._card('Race Condition Tester', `
      <p class="text-xs text-gray-400 mb-3">Send N identical requests simultaneously to test TOCTOU bugs (duplicate transactions, coupon reuse, etc.).</p>
      <div class="grid grid-cols-2 gap-3 mb-3">
        ${this._flowInput('race-flow')}
        ${this._input('race-concurrency', 'Concurrent Requests', '10', '10')}
      </div>
      <div class="mb-3">${this._btn("OffensiveTab.runRace()", "Fire Race Test", "bg-red-600 hover:bg-red-500")}</div>
      ${this._resultsDiv('race-results')}`);
  },

  async runRace() {
    const el = document.getElementById('race-results');
    el.innerHTML = '<div class="text-xs text-gray-500">Firing simultaneous requests...</div>';
    try {
      const data = await this._post('/api/exploit/race', {
        flow_id: document.getElementById('race-flow').value,
        concurrency: parseInt(document.getElementById('race-concurrency').value) || 10,
      });
      const statusDist = data.status_distribution || data.summary?.status_codes || {};
      el.innerHTML = `
        <div class="text-xs text-gray-400 mb-2">Method: ${esc(data.method)} | Concurrency: ${data.concurrency}</div>
        ${data.issues?.length ? data.issues.map(i => `<div class="text-xs bg-yellow-900/30 text-yellow-300 px-2 py-1 rounded mb-1">${esc(i)}</div>`).join('') : '<div class="text-xs text-green-400 mb-2">No obvious race condition indicators</div>'}
        <div class="flex gap-3 mb-3 text-xs">
          ${Object.entries(statusDist).map(([s,c]) => `<span class="${this._statusColor(parseInt(s))} font-bold">${s}: ${c}</span>`).join('')}
        </div>
        ${data.summary ? `<div class="bg-gray-900 rounded p-3 border border-gray-700 text-xs">
          <div>Avg: ${data.summary.avg_latency_ms?.toFixed(1)}ms | Min: ${data.summary.min_latency_ms?.toFixed(1)}ms | Max: ${data.summary.max_latency_ms?.toFixed(1)}ms</div>
          <div>Req/sec: ${data.summary.requests_per_sec?.toFixed(0)} | Errors: ${data.summary.error_count}</div>
        </div>` : ''}
        ${data.results ? `<div class="max-h-[200px] overflow-y-auto mt-2"><table class="w-full text-xs"><thead><tr class="text-gray-500 border-b border-gray-700">
          <th class="py-1 px-2">#</th><th class="py-1 px-2">Status</th><th class="py-1 px-2">Size</th><th class="py-1 px-2">Time</th>
        </tr></thead><tbody>
        ${data.results.map(r => `<tr class="border-b border-gray-800">
          <td class="py-1 px-2 text-center text-gray-500">${r.index??''}</td>
          <td class="py-1 px-2 text-center ${this._statusColor(r.status_code)}">${r.status_code||'ERR'}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.size||0}</td>
          <td class="py-1 px-2 text-center text-gray-400">${r.duration_ms?.toFixed(1)||0}ms</td>
        </tr>`).join('')}
        </tbody></table></div>` : ''}`;
    } catch(e) { el.innerHTML = `<div class="text-xs text-red-400">${esc(e.message)}</div>`; }
  },

  // ── Color helpers ────────────────────────────────────────

  _statusColor(code) {
    if (!code) return 'text-gray-500';
    if (code < 300) return 'text-green-400';
    if (code < 400) return 'text-blue-400';
    if (code < 500) return 'text-yellow-400';
    return 'text-red-400';
  },

  _methodColor(m) {
    const colors = {GET:'bg-green-900 text-green-300',POST:'bg-blue-900 text-blue-300',PUT:'bg-yellow-900 text-yellow-300',DELETE:'bg-red-900 text-red-300',PATCH:'bg-purple-900 text-purple-300'};
    return colors[m] || 'bg-gray-800 text-gray-300';
  },

  _typeColor(t) {
    const colors = {query:'bg-blue-900 text-blue-300',path:'bg-purple-900 text-purple-300',header:'bg-yellow-900 text-yellow-300',cookie:'bg-orange-900 text-orange-300',json:'bg-green-900 text-green-300',form:'bg-indigo-900 text-indigo-300'};
    return colors[t] || 'bg-gray-800 text-gray-300';
  },

  _severityBg(s) {
    const colors = {critical:'bg-red-900/50 text-red-300',high:'bg-orange-900/50 text-orange-300',medium:'bg-yellow-900/50 text-yellow-300',low:'bg-blue-900/50 text-blue-300',info:'bg-gray-800 text-gray-400'};
    return colors[s] || 'bg-gray-800 text-gray-400';
  },
};

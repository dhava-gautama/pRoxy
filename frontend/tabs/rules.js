// Rules tab: toggles, header rules, replace rules, breakpoints, scope, mock, map, highlight
window.RulesTab = {
  settings: null,

  _input: 'bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500',
  _btn: 'bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded',
  _btnSm: 'bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs px-2 py-1 rounded',

  render() {
    return `
      <div class="max-w-3xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <h2 class="text-lg font-bold text-white">Proxy Rules</h2>

        <div id="rules-loading" class="text-gray-500">Loading settings...</div>
        <div id="rules-content" class="hidden space-y-6">

          <!-- Toggles -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <h3 class="text-sm font-bold text-gray-400 uppercase">Response Manipulation</h3>
            <div class="space-y-2" id="toggle-section"></div>
          </div>

          <!-- Upstream Proxy -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-2">
            <h3 class="text-sm font-bold text-gray-400 uppercase">Upstream Proxy</h3>
            <span class="text-xs text-gray-500">Route traffic through another proxy (requires restart)</span>
            <div class="flex flex-wrap gap-1 mt-1 mb-2">
              <span class="text-xs bg-gray-800 text-indigo-400 px-2 py-0.5 rounded">http://host:port</span>
              <span class="text-xs bg-gray-800 text-indigo-400 px-2 py-0.5 rounded">https://host:port</span>
              <span class="text-xs bg-gray-800 text-green-400 px-2 py-0.5 rounded">socks5://host:port</span>
            </div>
            <div class="flex gap-2">
              <input id="upstream-input" type="text" placeholder="socks5://127.0.0.1:1080 or http://proxy:8080"
                class="flex-1 ${this._input}">
              <button onclick="RulesTab.saveUpstream()" class="${this._btn}">Save</button>
            </div>
          </div>

          <!-- Scope -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Scope</h3>
                <span class="text-xs text-gray-500">Only capture traffic matching these domains (glob). Empty = all.</span>
              </div>
              <button onclick="RulesTab.showForm('scope')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="scope-form" class="hidden"></div>
            <div id="scope-list" class="space-y-1"></div>
          </div>

          <!-- User-Agent -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-2">
            <h3 class="text-sm font-bold text-gray-400 uppercase">Custom User-Agent</h3>
            <div class="flex gap-2">
              <input id="ua-input" type="text" placeholder="Leave empty to use default"
                class="flex-1 ${this._input}">
              <button onclick="RulesTab.saveUA()" class="${this._btn}">Save</button>
            </div>
          </div>

          <!-- Header Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-bold text-gray-400 uppercase">Header Rules</h3>
              <button onclick="RulesTab.showForm('header')" class="text-xs ${this._btn}">+ Add Rule</button>
            </div>
            <div id="header-form" class="hidden"></div>
            <div id="header-rules-list" class="space-y-2"></div>
          </div>

          <!-- Replace Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Auto-Replace Rules</h3>
                <span class="text-xs text-gray-500">Find/replace in request or response bodies</span>
              </div>
              <button onclick="RulesTab.showForm('replace')" class="text-xs ${this._btn}">+ Add Rule</button>
            </div>
            <div id="replace-form" class="hidden"></div>
            <div id="replace-rules-list" class="space-y-2"></div>
          </div>

          <!-- Breakpoint Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Breakpoint Conditions</h3>
                <span class="text-xs text-gray-500">When intercept is on, only matching requests pause. No rules = all.</span>
              </div>
              <button onclick="RulesTab.showForm('breakpoint')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="breakpoint-form" class="hidden"></div>
            <div id="breakpoint-list" class="space-y-2"></div>
          </div>

          <!-- Mock Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Mock Rules</h3>
                <span class="text-xs text-gray-500">Return fake responses for matching URLs (bypasses server)</span>
              </div>
              <button onclick="RulesTab.showForm('mock')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="mock-form" class="hidden"></div>
            <div id="mock-rules-list" class="space-y-2"></div>
          </div>

          <!-- Map Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Map Rules</h3>
                <span class="text-xs text-gray-500">Map Local: serve file. Map Remote: rewrite URL to another host.</span>
              </div>
              <button onclick="RulesTab.showForm('map')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="map-form" class="hidden"></div>
            <div id="map-rules-list" class="space-y-2"></div>
          </div>

          <!-- Highlight Rules -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-sm font-bold text-gray-400 uppercase">Highlight Rules</h3>
                <span class="text-xs text-gray-500">Color-code traffic rows by host, path, method, status, or content-type</span>
              </div>
              <button onclick="RulesTab.showForm('highlight')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="highlight-form" class="hidden"></div>
            <div id="highlight-rules-list" class="space-y-2"></div>
          </div>

        </div>
      </div>`;
  },

  // ── Inline form management ────────────────────────────

  showForm(type) {
    const el = document.getElementById(type + '-form');
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }
    const I = this._input;
    const forms = {
      scope: `<div class="flex gap-2 items-end bg-gray-800/50 rounded p-3">
        <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Domain pattern (glob)</label>
        <input id="f-scope-pattern" class="w-full ${I}" placeholder="*.example.com"></div>
        <button onclick="RulesTab.submitScope()" class="${this._btn}">Add</button>
        <button onclick="RulesTab.hideForm('scope')" class="${this._btnSm}">Cancel</button>
      </div>`,
      header: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Header name</label>
          <input id="f-hdr-name" class="w-full ${I}" placeholder="X-Custom-Header"></div>
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Value</label>
          <input id="f-hdr-value" class="w-full ${I}" placeholder="value (leave empty for remove)"></div>
        </div>
        <div class="flex gap-2 items-end">
          <div><label class="text-xs text-gray-500 block mb-1">Phase</label>
          <select id="f-hdr-phase" class="${I}"><option value="request">request</option><option value="response" selected>response</option></select></div>
          <div><label class="text-xs text-gray-500 block mb-1">Action</label>
          <select id="f-hdr-action" class="${I}"><option value="set" selected>set</option><option value="remove">remove</option></select></div>
          <button onclick="RulesTab.submitHeader()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('header')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
      replace: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Search pattern</label>
          <input id="f-rep-pattern" class="w-full ${I}" placeholder="text or regex"></div>
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Replacement</label>
          <input id="f-rep-replacement" class="w-full ${I}" placeholder="replacement text"></div>
        </div>
        <div class="flex gap-2 items-end">
          <div><label class="text-xs text-gray-500 block mb-1">Phase</label>
          <select id="f-rep-phase" class="${I}"><option value="request">request</option><option value="response" selected>response</option></select></div>
          <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
            <input type="checkbox" id="f-rep-regex" class="accent-indigo-500"> Regex
          </label>
          <button onclick="RulesTab.submitReplace()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('replace')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
      breakpoint: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Host pattern (glob, empty=any)</label>
          <input id="f-bp-host" class="w-full ${I}" placeholder="*.api.com"></div>
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Path regex (empty=any)</label>
          <input id="f-bp-path" class="w-full ${I}" placeholder="/api/.*"></div>
          <div class="w-24"><label class="text-xs text-gray-500 block mb-1">Method</label>
          <input id="f-bp-method" class="w-full ${I}" placeholder="ANY"></div>
        </div>
        <div class="flex gap-2">
          <button onclick="RulesTab.submitBreakpoint()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('breakpoint')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
      mock: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">URL match pattern</label>
          <input id="f-mock-pattern" class="w-full ${I}" placeholder="*api.example.com/users*"></div>
          <div class="w-20"><label class="text-xs text-gray-500 block mb-1">Status</label>
          <input id="f-mock-status" type="number" class="w-full ${I}" value="200"></div>
        </div>
        <div><label class="text-xs text-gray-500 block mb-1">Response body</label>
        <textarea id="f-mock-body" rows="3" class="w-full ${I} font-mono" placeholder='{"key": "value"}'>{}</textarea></div>
        <div class="flex gap-2 items-center">
          <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
            <input type="checkbox" id="f-mock-regex" class="accent-indigo-500"> Regex
          </label>
          <button onclick="RulesTab.submitMock()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('mock')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
      map: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">URL match pattern</label>
          <input id="f-map-pattern" class="w-full ${I}" placeholder="*api.example.com*"></div>
          <div class="w-28"><label class="text-xs text-gray-500 block mb-1">Type</label>
          <select id="f-map-type" class="w-full ${I}"><option value="remote" selected>remote</option><option value="local">local</option></select></div>
        </div>
        <div><label class="text-xs text-gray-500 block mb-1">Target (URL for remote, file path for local)</label>
        <input id="f-map-target" class="w-full ${I}" placeholder="https://other-host.com/api or /path/to/file.json"></div>
        <div class="flex gap-2 items-center">
          <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
            <input type="checkbox" id="f-map-regex" class="accent-indigo-500"> Regex
          </label>
          <button onclick="RulesTab.submitMap()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('map')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
      highlight: `<div class="bg-gray-800/50 rounded p-3 space-y-2">
        <div class="flex gap-2">
          <div class="w-36"><label class="text-xs text-gray-500 block mb-1">Match on</label>
          <select id="f-hl-type" class="w-full ${I}">
            <option value="content-type">content-type</option><option value="host">host</option>
            <option value="path">path</option><option value="method">method</option><option value="status">status</option>
          </select></div>
          <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Pattern (regex)</label>
          <input id="f-hl-pattern" class="w-full ${I}" placeholder="json|image/png"></div>
          <div class="w-16"><label class="text-xs text-gray-500 block mb-1">Color</label>
          <input id="f-hl-color" type="color" value="#1e3a5f" class="w-full h-8 rounded border-0 cursor-pointer bg-transparent"></div>
        </div>
        <div class="flex gap-2">
          <button onclick="RulesTab.submitHighlight()" class="${this._btn}">Add</button>
          <button onclick="RulesTab.hideForm('highlight')" class="${this._btnSm}">Cancel</button>
        </div>
      </div>`,
    };
    el.innerHTML = forms[type] || '';
    el.classList.remove('hidden');
    const firstInput = el.querySelector('input[type="text"],input:not([type]),textarea');
    if (firstInput) firstInput.focus();
  },

  hideForm(type) {
    document.getElementById(type + '-form').classList.add('hidden');
  },

  // ── Load ──────────────────────────────────────────────

  async load() {
    try {
      const resp = await fetch('/api/settings');
      this.settings = await resp.json();
      document.getElementById('rules-loading').classList.add('hidden');
      document.getElementById('rules-content').classList.remove('hidden');
      this.renderToggles();
      this.renderHeaderRules();
      this.renderReplaceRules();
      this.renderBreakpoints();
      this.renderScope();
      this.renderMockRules();
      this.renderMapRules();
      this.renderHighlightRules();
      document.getElementById('ua-input').value = this.settings.custom_user_agent || '';
      document.getElementById('upstream-input').value = this.settings.upstream_proxy || '';
    } catch (e) {
      Toast.show('Failed to load settings', 'error');
    }
  },

  renderToggles() {
    const toggles = [
      { key: 'hsts_strip', label: 'Strip HSTS', desc: 'Remove Strict-Transport-Security headers' },
      { key: 'hpkp_strip', label: 'Strip HPKP & Expect-CT', desc: 'Remove Public-Key-Pins and Expect-CT headers' },
      { key: 'csp_strip', label: 'Strip CSP', desc: 'Remove Content-Security-Policy headers' },
      { key: 'cors_bypass', label: 'CORS Bypass', desc: 'Inject permissive CORS headers' },
      { key: 'force_ssl', label: 'Force SSL', desc: 'Upgrade HTTP requests to HTTPS' },
      { key: 'intercept_enabled', label: 'Intercept Requests', desc: 'Pause requests for manual review' },
      { key: 'intercept_responses', label: 'Intercept Responses', desc: 'Also pause responses for editing' },
    ];
    document.getElementById('toggle-section').innerHTML = toggles.map(t => `
      <div class="flex items-center justify-between">
        <div>
          <span class="text-gray-200 text-sm">${t.label}</span>
          <span class="text-gray-500 text-xs ml-2">${t.desc}</span>
        </div>
        <label class="toggle-switch">
          <input type="checkbox" ${this.settings[t.key] ? 'checked' : ''} onchange="RulesTab.toggle('${t.key}', this.checked)">
          <span class="toggle-slider"></span>
        </label>
      </div>
    `).join('');
  },

  async toggle(key, value) {
    try {
      const resp = await fetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: value })
      });
      this.settings = await resp.json();
      Toast.show(`${key} ${value ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) { Toast.show('Failed to update', 'error'); }
  },

  async saveUpstream() {
    const val = document.getElementById('upstream-input').value;
    await this._save({ upstream_proxy: val });
    Toast.show('Upstream proxy saved (restart required to apply)', 'info', 5000);
  },

  async saveUA() {
    const ua = document.getElementById('ua-input').value;
    try {
      const resp = await fetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ custom_user_agent: ua })
      });
      this.settings = await resp.json();
      Toast.show('User-Agent saved', 'success');
    } catch (e) { Toast.show('Failed to save', 'error'); }
  },

  async _save(patch) {
    try {
      const resp = await fetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch)
      });
      this.settings = await resp.json();
    } catch (e) { Toast.show('Failed to save', 'error'); }
  },

  // ── Scope ──────────────────────────────────────────────

  renderScope() {
    const list = this.settings.scope_patterns || [];
    document.getElementById('scope-list').innerHTML = list.length === 0
      ? '<div class="text-gray-600 text-xs">No scope defined — capturing all traffic</div>'
      : list.map((p, i) => `
        <div class="flex items-center justify-between bg-gray-800 rounded px-3 py-1.5 text-xs">
          <span class="text-indigo-400">${esc(p)}</span>
          <button onclick="RulesTab.removeScope(${i})" class="text-red-400 hover:text-red-300">✕</button>
        </div>
      `).join('');
  },

  submitScope() {
    const v = document.getElementById('f-scope-pattern').value.trim();
    if (!v) return;
    const list = [...(this.settings.scope_patterns || []), v];
    this._save({ scope_patterns: list }).then(() => { this.renderScope(); this.hideForm('scope'); });
  },

  removeScope(i) {
    const list = this.settings.scope_patterns.filter((_, idx) => idx !== i);
    this._save({ scope_patterns: list }).then(() => this.renderScope());
  },

  // ── Header Rules ───────────────────────────────────────

  renderHeaderRules() {
    const rules = this.settings.header_rules || [];
    document.getElementById('header-rules-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No header rules configured</div>'
      : rules.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded p-2 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleHeaderRule(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          <span class="text-indigo-400 w-16">${r.phase}</span>
          <span class="text-yellow-400 w-14">${r.action}</span>
          <span class="text-gray-200">${esc(r.name)}</span>
          ${r.action === 'set' ? `<span class="text-gray-500">:</span> <span class="text-gray-300">${esc(r.value)}</span>` : ''}
          <button onclick="RulesTab.removeHeaderRule(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
        </div>
      `).join('');
  },

  submitHeader() {
    const name = document.getElementById('f-hdr-name').value.trim();
    if (!name) return;
    const value = document.getElementById('f-hdr-value').value;
    const phase = document.getElementById('f-hdr-phase').value;
    const action = document.getElementById('f-hdr-action').value;
    const rules = [...(this.settings.header_rules || []), { name, value, phase, action, enabled: true }];
    this._save({ header_rules: rules }).then(() => { this.renderHeaderRules(); this.hideForm('header'); });
  },

  toggleHeaderRule(i, enabled) {
    const rules = [...this.settings.header_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ header_rules: rules }).then(() => this.renderHeaderRules());
  },

  removeHeaderRule(i) {
    const rules = this.settings.header_rules.filter((_, idx) => idx !== i);
    this._save({ header_rules: rules }).then(() => this.renderHeaderRules());
  },

  // ── Replace Rules ──────────────────────────────────────

  renderReplaceRules() {
    const rules = this.settings.replace_rules || [];
    document.getElementById('replace-rules-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No replace rules configured</div>'
      : rules.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded p-2 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleReplaceRule(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          <span class="text-indigo-400 w-16">${r.phase}</span>
          <span class="${r.is_regex ? 'text-purple-400' : 'text-gray-400'} w-10">${r.is_regex ? 'regex' : 'text'}</span>
          <span class="text-red-300">${esc(r.pattern)}</span>
          <span class="text-gray-500">→</span>
          <span class="text-green-300">${esc(r.replacement)}</span>
          <button onclick="RulesTab.removeReplaceRule(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
        </div>
      `).join('');
  },

  submitReplace() {
    const pattern = document.getElementById('f-rep-pattern').value.trim();
    if (!pattern) return;
    const replacement = document.getElementById('f-rep-replacement').value;
    const phase = document.getElementById('f-rep-phase').value;
    const is_regex = document.getElementById('f-rep-regex').checked;
    const rules = [...(this.settings.replace_rules || []), { pattern, replacement, phase, is_regex, enabled: true }];
    this._save({ replace_rules: rules }).then(() => { this.renderReplaceRules(); this.hideForm('replace'); });
  },

  toggleReplaceRule(i, enabled) {
    const rules = [...this.settings.replace_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ replace_rules: rules }).then(() => this.renderReplaceRules());
  },

  removeReplaceRule(i) {
    const rules = this.settings.replace_rules.filter((_, idx) => idx !== i);
    this._save({ replace_rules: rules }).then(() => this.renderReplaceRules());
  },

  // ── Breakpoints ────────────────────────────────────────

  renderBreakpoints() {
    const rules = this.settings.breakpoint_rules || [];
    document.getElementById('breakpoint-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No breakpoint conditions — intercept captures all</div>'
      : rules.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded p-2 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleBreakpoint(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          ${r.method ? `<span class="text-yellow-400 w-10">${esc(r.method)}</span>` : '<span class="text-gray-600 w-10">ANY</span>'}
          ${r.host_pattern ? `<span class="text-indigo-400">${esc(r.host_pattern)}</span>` : ''}
          ${r.path_pattern ? `<span class="text-purple-400">${esc(r.path_pattern)}</span>` : ''}
          <button onclick="RulesTab.removeBreakpoint(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
        </div>
      `).join('');
  },

  submitBreakpoint() {
    const host_pattern = document.getElementById('f-bp-host').value.trim();
    const path_pattern = document.getElementById('f-bp-path').value.trim();
    const method = document.getElementById('f-bp-method').value.trim().toUpperCase();
    const rules = [...(this.settings.breakpoint_rules || []), { host_pattern, path_pattern, method, enabled: true }];
    this._save({ breakpoint_rules: rules }).then(() => { this.renderBreakpoints(); this.hideForm('breakpoint'); });
  },

  toggleBreakpoint(i, enabled) {
    const rules = [...this.settings.breakpoint_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ breakpoint_rules: rules }).then(() => this.renderBreakpoints());
  },

  removeBreakpoint(i) {
    const rules = this.settings.breakpoint_rules.filter((_, idx) => idx !== i);
    this._save({ breakpoint_rules: rules }).then(() => this.renderBreakpoints());
  },

  // ── Mock Rules ────────────────────────────────────────

  renderMockRules() {
    const rules = this.settings.mock_rules || [];
    document.getElementById('mock-rules-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No mock rules configured</div>'
      : rules.map((r, i) => `
        <div class="bg-gray-800 rounded p-2 text-xs space-y-1">
          <div class="flex items-center gap-2">
            <label class="toggle-switch" style="width:36px;height:20px">
              <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleMockRule(${i}, this.checked)">
              <span class="toggle-slider" style="border-radius:10px"></span>
            </label>
            <span class="${r.is_regex ? 'text-purple-400' : 'text-indigo-400'}">${r.is_regex ? 'regex' : 'glob'}</span>
            <span class="text-gray-200">${esc(r.match_pattern)}</span>
            <span class="text-yellow-400">→ ${r.status_code}</span>
            <button onclick="RulesTab.removeMockRule(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
          </div>
          <textarea rows="2" class="w-full bg-gray-900 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 font-mono"
            onchange="RulesTab.updateMockBody(${i}, this.value)">${esc(r.body)}</textarea>
        </div>
      `).join('');
  },

  submitMock() {
    const match_pattern = document.getElementById('f-mock-pattern').value.trim();
    if (!match_pattern) return;
    const is_regex = document.getElementById('f-mock-regex').checked;
    const status_code = parseInt(document.getElementById('f-mock-status').value, 10) || 200;
    const body = document.getElementById('f-mock-body').value;
    const rules = [...(this.settings.mock_rules || []), { match_pattern, is_regex, status_code, headers: {"Content-Type": "application/json"}, body, enabled: true }];
    this._save({ mock_rules: rules }).then(() => { this.renderMockRules(); this.hideForm('mock'); });
  },

  toggleMockRule(i, enabled) {
    const rules = [...this.settings.mock_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ mock_rules: rules }).then(() => this.renderMockRules());
  },

  removeMockRule(i) {
    const rules = this.settings.mock_rules.filter((_, idx) => idx !== i);
    this._save({ mock_rules: rules }).then(() => this.renderMockRules());
  },

  updateMockBody(i, body) {
    const rules = [...this.settings.mock_rules];
    rules[i] = { ...rules[i], body };
    this._save({ mock_rules: rules });
  },

  // ── Map Rules ─────────────────────────────────────────

  renderMapRules() {
    const rules = this.settings.map_rules || [];
    document.getElementById('map-rules-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No map rules configured</div>'
      : rules.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded p-2 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleMapRule(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          <span class="${r.rule_type === 'local' ? 'text-green-400' : 'text-blue-400'} w-14">${r.rule_type}</span>
          <span class="${r.is_regex ? 'text-purple-400' : 'text-gray-400'} w-10">${r.is_regex ? 'regex' : 'glob'}</span>
          <span class="text-gray-200">${esc(r.match_pattern)}</span>
          <span class="text-gray-500">→</span>
          <span class="text-indigo-300 truncate">${esc(r.target)}</span>
          <button onclick="RulesTab.removeMapRule(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
        </div>
      `).join('');
  },

  submitMap() {
    const match_pattern = document.getElementById('f-map-pattern').value.trim();
    if (!match_pattern) return;
    const target = document.getElementById('f-map-target').value.trim();
    if (!target) return;
    const is_regex = document.getElementById('f-map-regex').checked;
    const rule_type = document.getElementById('f-map-type').value;
    const rules = [...(this.settings.map_rules || []), { match_pattern, is_regex, rule_type, target, enabled: true }];
    this._save({ map_rules: rules }).then(() => { this.renderMapRules(); this.hideForm('map'); });
  },

  toggleMapRule(i, enabled) {
    const rules = [...this.settings.map_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ map_rules: rules }).then(() => this.renderMapRules());
  },

  removeMapRule(i) {
    const rules = this.settings.map_rules.filter((_, idx) => idx !== i);
    this._save({ map_rules: rules }).then(() => this.renderMapRules());
  },

  // ── Highlight Rules ───────────────────────────────────

  renderHighlightRules() {
    const rules = this.settings.highlight_rules || [];
    document.getElementById('highlight-rules-list').innerHTML = rules.length === 0
      ? '<div class="text-gray-600 text-xs">No highlight rules configured</div>'
      : rules.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded p-2 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="RulesTab.toggleHighlightRule(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          <span class="text-indigo-400 w-24">${esc(r.match_type)}</span>
          <span class="text-gray-200">${esc(r.pattern)}</span>
          <input type="color" value="${r.color}" onchange="RulesTab.updateHighlightColor(${i}, this.value)" class="w-6 h-6 rounded border-0 cursor-pointer" style="background:transparent">
          <span class="w-4 h-4 rounded" style="background:${r.color}"></span>
          <button onclick="RulesTab.removeHighlightRule(${i})" class="ml-auto text-red-400 hover:text-red-300 px-1">✕</button>
        </div>
      `).join('');
  },

  submitHighlight() {
    const match_type = document.getElementById('f-hl-type').value;
    const pattern = document.getElementById('f-hl-pattern').value.trim();
    if (!pattern) return;
    const color = document.getElementById('f-hl-color').value;
    const rules = [...(this.settings.highlight_rules || []), { match_type, pattern, color, enabled: true }];
    this._save({ highlight_rules: rules }).then(() => { this.renderHighlightRules(); this.hideForm('highlight'); });
  },

  toggleHighlightRule(i, enabled) {
    const rules = [...this.settings.highlight_rules];
    rules[i] = { ...rules[i], enabled };
    this._save({ highlight_rules: rules }).then(() => this.renderHighlightRules());
  },

  updateHighlightColor(i, color) {
    const rules = [...this.settings.highlight_rules];
    rules[i] = { ...rules[i], color };
    this._save({ highlight_rules: rules });
  },

  removeHighlightRule(i) {
    const rules = this.settings.highlight_rules.filter((_, idx) => idx !== i);
    this._save({ highlight_rules: rules }).then(() => this.renderHighlightRules());
  },
};

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

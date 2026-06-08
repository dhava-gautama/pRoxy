// Rules tab: toggles, header rules, replace rules, breakpoints, scope, mock, map, highlight
window.RulesTab = {
  settings: null,
  _editingHeaderIndex: -1,
  _editingReplaceIndex: -1,
  _editingScopeIndex: -1,
  _editingBreakpointIndex: -1,
  _editingMapIndex: -1,
  _editingMockIndex: -1,
  _editingHighlightIndex: -1,

  _input: 'bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500',
  _btn: 'bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded',
  _btnSm: 'bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs px-2 py-1 rounded',

  render() {
    return `
      <div class="max-w-4xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-white">Proxy Rules</h2>
          <div class="flex gap-2">
            <button onclick="RulesTab.showTemplates()" class="text-xs bg-purple-600 hover:bg-purple-500 text-white px-3 py-1.5 rounded">
              📋 Templates
            </button>
            <button onclick="RulesTab.showCollections()" class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded">
              📁 Collections
            </button>
            <button onclick="RulesTab.showImportExport()" class="text-xs bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded">
              💾 Import/Export
            </button>
          </div>
        </div>

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

        <!-- Templates Modal -->
        <div id="templates-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Rule Templates</h3>
              <button onclick="document.getElementById('templates-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
            </div>
            <div id="templates-content" class="space-y-4"></div>
          </div>
        </div>

        <!-- Collections Modal -->
        <div id="collections-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Rule Collections</h3>
              <div class="flex gap-2">
                <button onclick="RulesTab.createCollection()" class="text-xs bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded">+ New Collection</button>
                <button onclick="document.getElementById('collections-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
              </div>
            </div>
            <div id="collections-content" class="space-y-4"></div>
          </div>
        </div>

        <!-- Import/Export Modal -->
        <div id="import-export-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-2xl" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Import/Export Rules</h3>
              <button onclick="document.getElementById('import-export-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
            </div>

            <div class="space-y-4">
              <div class="bg-gray-800 rounded-lg p-4">
                <h4 class="text-sm font-bold text-gray-300 mb-2">Export Current Rules</h4>
                <div class="flex gap-2">
                  <button onclick="RulesTab.exportRules('json')" class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded">
                    📄 JSON
                  </button>
                  <button onclick="RulesTab.exportRules('yaml')" class="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded">
                    📄 YAML
                  </button>
                </div>
              </div>

              <div class="bg-gray-800 rounded-lg p-4">
                <h4 class="text-sm font-bold text-gray-300 mb-2">Import Rules</h4>
                <div class="space-y-2">
                  <input type="file" id="import-file" accept=".json,.yaml,.yml" class="text-xs text-gray-300 w-full">
                  <div class="flex gap-2 items-center">
                    <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
                      <input type="checkbox" id="import-merge" checked class="accent-indigo-500"> Merge with existing
                    </label>
                    <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer">
                      <input type="checkbox" id="import-backup" checked class="accent-indigo-500"> Backup current
                    </label>
                  </div>
                  <button onclick="RulesTab.importRules()" class="text-xs bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded">
                    📥 Import Rules
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>`;
  },

  // ── Inline form management ────────────────────────────

  showForm(type) {
    const el = document.getElementById(type + '-form');
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }

    // Reset editing state when showing form for adding new rule
    if (type === 'header') this._editingHeaderIndex = -1;
    if (type === 'replace') this._editingReplaceIndex = -1;
    if (type === 'scope') this._editingScopeIndex = -1;
    if (type === 'breakpoint') this._editingBreakpointIndex = -1;
    if (type === 'map') this._editingMapIndex = -1;
    if (type === 'mock') this._editingMockIndex = -1;
    if (type === 'highlight') this._editingHighlightIndex = -1;

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
      const resp = await authFetch('/api/settings');
      if (!resp.ok) { Toast.show('Failed to load settings', 'error'); return; }
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
      const resp = await authFetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [key]: value })
      });
      if (!resp.ok) { Toast.show('Failed to update', 'error'); return; }
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
      const resp = await authFetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ custom_user_agent: ua })
      });
      if (!resp.ok) { Toast.show('Failed to save', 'error'); return; }
      this.settings = await resp.json();
      Toast.show('User-Agent saved', 'success');
    } catch (e) { Toast.show('Failed to save', 'error'); }
  },

  async _save(patch) {
    try {
      const resp = await authFetch('/api/settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch)
      });
      if (!resp.ok) { Toast.show('Failed to save', 'error'); return; }
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
          <div class="flex gap-1">
            <button onclick="RulesTab.editScope(${i})" class="text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
            <button onclick="RulesTab.removeScope(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
          </div>
        </div>
      `).join('');
  },

  submitScope() {
    const v = document.getElementById('f-scope-pattern').value.trim();
    if (!v) return;

    let list = [...(this.settings.scope_patterns || [])];

    if (this._editingScopeIndex >= 0) {
      // Edit mode - update existing pattern
      list[this._editingScopeIndex] = v;
      this._editingScopeIndex = -1;
    } else {
      // Add mode - append new pattern
      list.push(v);
    }

    this._save({ scope_patterns: list }).then(() => { this.renderScope(); this.hideForm('scope'); });
  },

  removeScope(i) {
    const list = this.settings.scope_patterns.filter((_, idx) => idx !== i);
    this._save({ scope_patterns: list }).then(() => this.renderScope());
  },

  editScope(i) {
    const pattern = this.settings.scope_patterns[i];
    this._editingScopeIndex = i;

    // Show form and populate with existing value
    this.showForm('scope');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-scope-pattern').value = pattern;

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#scope-form button[onclick*="submitScope"]');
      if (submitBtn) submitBtn.textContent = 'Update';
    }, 10);
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
          <button onclick="RulesTab.editHeaderRule(${i})" class="ml-auto text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
          <button onclick="RulesTab.removeHeaderRule(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
        </div>
      `).join('');
  },

  submitHeader() {
    const name = document.getElementById('f-hdr-name').value.trim();
    if (!name) return;
    const value = document.getElementById('f-hdr-value').value;
    const phase = document.getElementById('f-hdr-phase').value;
    const action = document.getElementById('f-hdr-action').value;

    let rules = [...(this.settings.header_rules || [])];

    if (this._editingHeaderIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingHeaderIndex] = { ...rules[this._editingHeaderIndex], name, value, phase, action };
      this._editingHeaderIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ name, value, phase, action, enabled: true });
    }

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

  editHeaderRule(i) {
    const rule = this.settings.header_rules[i];
    this._editingHeaderIndex = i;

    // Show form and populate with existing values
    this.showForm('header');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-hdr-name').value = rule.name;
      document.getElementById('f-hdr-value').value = rule.value || '';
      document.getElementById('f-hdr-phase').value = rule.phase;
      document.getElementById('f-hdr-action').value = rule.action;

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#header-form button[onclick*="submitHeader"]');
      if (submitBtn) submitBtn.textContent = 'Update Rule';
    }, 10);
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
          <button onclick="RulesTab.editReplaceRule(${i})" class="ml-auto text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
          <button onclick="RulesTab.removeReplaceRule(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
        </div>
      `).join('');
  },

  submitReplace() {
    const pattern = document.getElementById('f-rep-pattern').value.trim();
    if (!pattern) return;
    const replacement = document.getElementById('f-rep-replacement').value;
    const phase = document.getElementById('f-rep-phase').value;
    const is_regex = document.getElementById('f-rep-regex').checked;

    let rules = [...(this.settings.replace_rules || [])];

    if (this._editingReplaceIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingReplaceIndex] = { ...rules[this._editingReplaceIndex], pattern, replacement, phase, is_regex };
      this._editingReplaceIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ pattern, replacement, phase, is_regex, enabled: true });
    }

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

  editReplaceRule(i) {
    const rule = this.settings.replace_rules[i];
    this._editingReplaceIndex = i;

    // Show form and populate with existing values
    this.showForm('replace');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-rep-pattern').value = rule.pattern;
      document.getElementById('f-rep-replacement').value = rule.replacement || '';
      document.getElementById('f-rep-phase').value = rule.phase;
      document.getElementById('f-rep-regex').checked = rule.is_regex || false;

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#replace-form button[onclick*="submitReplace"]');
      if (submitBtn) submitBtn.textContent = 'Update Rule';
    }, 10);
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
          <div class="ml-auto flex gap-1">
            <button onclick="RulesTab.editBreakpoint(${i})" class="text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
            <button onclick="RulesTab.removeBreakpoint(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
          </div>
        </div>
      `).join('');
  },

  submitBreakpoint() {
    const host_pattern = document.getElementById('f-bp-host').value.trim();
    const path_pattern = document.getElementById('f-bp-path').value.trim();
    const method = document.getElementById('f-bp-method').value.trim().toUpperCase();

    let rules = [...(this.settings.breakpoint_rules || [])];

    if (this._editingBreakpointIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingBreakpointIndex] = { ...rules[this._editingBreakpointIndex], host_pattern, path_pattern, method };
      this._editingBreakpointIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ host_pattern, path_pattern, method, enabled: true });
    }

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

  editBreakpoint(i) {
    const rule = this.settings.breakpoint_rules[i];
    this._editingBreakpointIndex = i;

    // Show form and populate with existing values
    this.showForm('breakpoint');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-bp-host').value = rule.host_pattern || '';
      document.getElementById('f-bp-path').value = rule.path_pattern || '';
      document.getElementById('f-bp-method').value = rule.method || '';

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#breakpoint-form button[onclick*="submitBreakpoint"]');
      if (submitBtn) submitBtn.textContent = 'Update';
    }, 10);
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
            <div class="ml-auto flex gap-1">
              <button onclick="RulesTab.editMockRule(${i})" class="text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
              <button onclick="RulesTab.removeMockRule(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
            </div>
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

    let rules = [...(this.settings.mock_rules || [])];

    if (this._editingMockIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingMockIndex] = { ...rules[this._editingMockIndex], match_pattern, is_regex, status_code, body };
      this._editingMockIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ match_pattern, is_regex, status_code, headers: {"Content-Type": "application/json"}, body, enabled: true });
    }

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

  editMockRule(i) {
    const rule = this.settings.mock_rules[i];
    this._editingMockIndex = i;

    // Show form and populate with existing values
    this.showForm('mock');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-mock-pattern').value = rule.match_pattern || '';
      document.getElementById('f-mock-status').value = rule.status_code || 200;
      document.getElementById('f-mock-body').value = rule.body || '';
      document.getElementById('f-mock-regex').checked = rule.is_regex || false;

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#mock-form button[onclick*="submitMock"]');
      if (submitBtn) submitBtn.textContent = 'Update';
    }, 10);
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
          <div class="ml-auto flex gap-1">
            <button onclick="RulesTab.editMapRule(${i})" class="text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
            <button onclick="RulesTab.removeMapRule(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
          </div>
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

    let rules = [...(this.settings.map_rules || [])];

    if (this._editingMapIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingMapIndex] = { ...rules[this._editingMapIndex], match_pattern, is_regex, rule_type, target };
      this._editingMapIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ match_pattern, is_regex, rule_type, target, enabled: true });
    }

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

  editMapRule(i) {
    const rule = this.settings.map_rules[i];
    this._editingMapIndex = i;

    // Show form and populate with existing values
    this.showForm('map');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-map-pattern').value = rule.match_pattern || '';
      document.getElementById('f-map-target').value = rule.target || '';
      document.getElementById('f-map-type').value = rule.rule_type || 'remote';
      document.getElementById('f-map-regex').checked = rule.is_regex || false;

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#map-form button[onclick*="submitMap"]');
      if (submitBtn) submitBtn.textContent = 'Update';
    }, 10);
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
          <div class="ml-auto flex gap-1">
            <button onclick="RulesTab.editHighlightRule(${i})" class="text-blue-400 hover:text-blue-300 px-1" title="Edit">✎</button>
            <button onclick="RulesTab.removeHighlightRule(${i})" class="text-red-400 hover:text-red-300 px-1" title="Delete">✕</button>
          </div>
        </div>
      `).join('');
  },

  submitHighlight() {
    const match_type = document.getElementById('f-hl-type').value;
    const pattern = document.getElementById('f-hl-pattern').value.trim();
    if (!pattern) return;
    const color = document.getElementById('f-hl-color').value;

    let rules = [...(this.settings.highlight_rules || [])];

    if (this._editingHighlightIndex >= 0) {
      // Edit mode - update existing rule
      rules[this._editingHighlightIndex] = { ...rules[this._editingHighlightIndex], match_type, pattern, color };
      this._editingHighlightIndex = -1;
    } else {
      // Add mode - append new rule
      rules.push({ match_type, pattern, color, enabled: true });
    }

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

  editHighlightRule(i) {
    const rule = this.settings.highlight_rules[i];
    this._editingHighlightIndex = i;

    // Show form and populate with existing values
    this.showForm('highlight');

    // Wait for form to be rendered, then populate
    setTimeout(() => {
      document.getElementById('f-hl-type').value = rule.match_type || 'content-type';
      document.getElementById('f-hl-pattern').value = rule.pattern || '';
      document.getElementById('f-hl-color').value = rule.color || '#1e3a5f';

      // Change button text to indicate edit mode
      const submitBtn = document.querySelector('#highlight-form button[onclick*="submitHighlight"]');
      if (submitBtn) submitBtn.textContent = 'Update';
    }, 10);
  },

  // ── Enhanced Rule Management ───────────────────────────────────────

  async showTemplates() {
    const modal = document.getElementById('templates-modal');
    const content = document.getElementById('templates-content');

    try {
      const resp = await authFetch('/api/rules/templates');
      const data = await resp.json();

      content.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          ${data.templates.map(template => `
            <div class="bg-gray-800 rounded-lg p-4 space-y-2">
              <div class="flex items-start justify-between">
                <div>
                  <h4 class="text-white font-semibold">${esc(template.name)}</h4>
                  <div class="flex gap-1 mt-1">
                    <span class="text-xs px-2 py-0.5 rounded bg-${this._getCategoryColor(template.category)} text-white">
                      ${template.category}
                    </span>
                    <span class="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300">
                      ${template.difficulty}
                    </span>
                  </div>
                </div>
                <button onclick="RulesTab.applyTemplate('${template.id}')"
                  class="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded">
                  Apply
                </button>
              </div>
              <p class="text-xs text-gray-400">${esc(template.description)}</p>
              <div class="flex flex-wrap gap-1">
                ${template.tags.map(tag => `
                  <span class="text-xs bg-gray-700 text-gray-300 px-1 py-0.5 rounded">#${tag}</span>
                `).join('')}
              </div>
              <div class="text-xs text-gray-500">
                Rules: ${Object.values(template.rules).reduce((sum, rules) => sum + (Array.isArray(rules) ? rules.length : 1), 0)}
              </div>
            </div>
          `).join('')}
        </div>
      `;

      modal.classList.remove('hidden');
    } catch (e) {
      Toast.show('Failed to load templates', 'error');
    }
  },

  _getCategoryColor(category) {
    const colors = {
      'pentest': 'red-600',
      'bypass': 'yellow-600',
      'analysis': 'blue-600',
      'recon': 'purple-600'
    };
    return colors[category] || 'gray-600';
  },

  async applyTemplate(templateId) {
    try {
      const resp = await authFetch(`/api/rules/templates/${templateId}/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          merge: true,
          backup_current: true
        })
      });

      const result = await resp.json();
      Toast.show(`Template applied: ${result.rules_added} rules added`, 'success');

      // Refresh the rules display
      this.load();

      // Close template modal
      document.getElementById('templates-modal').classList.add('hidden');
    } catch (e) {
      Toast.show('Failed to apply template', 'error');
    }
  },

  async showCollections() {
    const modal = document.getElementById('collections-modal');
    const content = document.getElementById('collections-content');

    try {
      const resp = await authFetch('/api/rules/collections');
      const data = await resp.json();

      if (data.collections.length === 0) {
        content.innerHTML = `
          <div class="text-center py-8 text-gray-500">
            <div class="text-4xl mb-2">📂</div>
            <p>No rule collections saved yet.</p>
            <p class="text-xs">Create collections to organize your rules for different projects.</p>
          </div>
        `;
      } else {
        content.innerHTML = `
          <div class="space-y-3">
            ${data.collections.map(collection => `
              <div class="bg-gray-800 rounded-lg p-4 flex items-center justify-between">
                <div class="flex-1">
                  <h4 class="text-white font-semibold">${esc(collection.name)}</h4>
                  <p class="text-xs text-gray-400">${esc(collection.description)}</p>
                  <div class="flex gap-2 mt-2">
                    ${collection.tags.map(tag => `
                      <span class="text-xs bg-gray-700 text-gray-300 px-1 py-0.5 rounded">#${tag}</span>
                    `).join('')}
                  </div>
                  <div class="text-xs text-gray-500 mt-1">
                    Author: ${collection.author || 'Unknown'} | Version: ${collection.version}
                  </div>
                </div>
                <div class="flex gap-1">
                  <button onclick="RulesTab.applyCollection('${collection.id}')"
                    class="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded">
                    Apply
                  </button>
                  <button onclick="RulesTab.deleteCollection('${collection.id}')"
                    class="text-xs bg-red-600 hover:bg-red-500 text-white px-2 py-1 rounded">
                    Delete
                  </button>
                </div>
              </div>
            `).join('')}
          </div>
        `;
      }

      modal.classList.remove('hidden');
    } catch (e) {
      Toast.show('Failed to load collections', 'error');
    }
  },

  async createCollection() {
    const name = prompt('Collection name:');
    if (!name) return;

    const description = prompt('Collection description (optional):') || '';
    const tags = prompt('Tags (comma-separated, optional):');

    try {
      const collection = {
        name,
        description,
        tags: tags ? tags.split(',').map(t => t.trim()) : [],
        rules: this.settings
      };

      const resp = await authFetch('/api/rules/collections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(collection)
      });

      await resp.json();
      Toast.show(`Collection "${name}" created`, 'success');

      // Refresh collections display
      this.showCollections();
    } catch (e) {
      Toast.show('Failed to create collection', 'error');
    }
  },

  async applyCollection(collectionId) {
    try {
      const resp = await authFetch(`/api/rules/collections/${collectionId}/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          merge: true,
          backup_current: true
        })
      });

      await resp.json();
      Toast.show('Collection applied successfully', 'success');

      // Refresh the rules display
      this.load();

      // Close collections modal
      document.getElementById('collections-modal').classList.add('hidden');
    } catch (e) {
      Toast.show('Failed to apply collection', 'error');
    }
  },

  async deleteCollection(collectionId) {
    if (!confirm('Are you sure you want to delete this collection?')) return;

    try {
      await authFetch(`/api/rules/collections/${collectionId}`, { method: 'DELETE' });
      Toast.show('Collection deleted', 'success');

      // Refresh collections display
      this.showCollections();
    } catch (e) {
      Toast.show('Failed to delete collection', 'error');
    }
  },

  showImportExport() {
    document.getElementById('import-export-modal').classList.remove('hidden');
  },

  async exportRules(format) {
    try {
      const resp = await authFetch(`/api/rules/export?format=${format}&include_settings=true&include_metadata=true`);

      if (!resp.ok) throw new Error('Export failed');

      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = resp.headers.get('content-disposition')?.split('filename=')[1] || `rules.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      Toast.show(`Rules exported as ${format.toUpperCase()}`, 'success');
    } catch (e) {
      Toast.show('Failed to export rules', 'error');
    }
  },

  async importRules() {
    const fileInput = document.getElementById('import-file');
    const file = fileInput.files[0];

    if (!file) {
      Toast.show('Please select a file to import', 'error');
      return;
    }

    const merge = document.getElementById('import-merge').checked;
    const backup = document.getElementById('import-backup').checked;

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('merge', merge);
      formData.append('backup_current', backup);

      const resp = await authFetch('/api/rules/import', {
        method: 'POST',
        body: formData
      });

      const result = await resp.json();

      if (result.valid === false) {
        Toast.show('Import validation failed: ' + result.errors.join(', '), 'error');
        return;
      }

      Toast.show('Rules imported successfully', 'success');

      // Refresh the rules display
      this.load();

      // Close import/export modal
      document.getElementById('import-export-modal').classList.add('hidden');

      // Clear file input
      fileInput.value = '';
    } catch (e) {
      Toast.show('Failed to import rules', 'error');
    }
  },

  async getRuleStatistics() {
    try {
      const resp = await authFetch('/api/rules/statistics');
      const stats = await resp.json();

      console.log('Rule Statistics:', stats);
      return stats;
    } catch (e) {
      Toast.show('Failed to get rule statistics', 'error');
    }
  }
};

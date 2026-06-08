// OpenAPI / Swagger export — generates an OpenAPI 3.0 spec from captured traffic.
const OpenAPITab = {
  spec: null,

  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">OpenAPI / Swagger Export</h2>
          <p class="text-xs text-gray-500">Reverse-engineer an OpenAPI 3.0 spec from captured traffic — path templating and JSON schema inference are automatic.</p>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Domain filter (substring of host)</label>
            <input id="oapi-domain" class="bg-gray-900 text-gray-200 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder="e.g. api.example.com" style="width:280px">
          </div>
          <label class="flex items-center gap-2 text-xs text-gray-300 pb-2" title="Embeds real captured bodies verbatim — may contain tokens/PII. Local use only.">
            <input id="oapi-examples" type="checkbox" class="accent-indigo-500">
            Include examples <span class="text-amber-500">(may leak secrets)</span>
          </label>
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Format</label>
            <select id="oapi-format" class="bg-gray-900 text-gray-200 text-xs px-2 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
              <option value="json">JSON</option>
              <option value="yaml">YAML</option>
            </select>
          </div>
          <button onclick="OpenAPITab.load()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-2 rounded">Discover endpoints</button>
          <button onclick="OpenAPITab.generate()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-2 rounded">Generate spec</button>
        </div>

        <div>
          <h3 class="text-sm font-bold text-gray-300 mb-2">Discovered endpoints</h3>
          <div id="oapi-endpoints" class="space-y-1 text-xs"><div class="text-gray-500">Click "Discover endpoints" to scan captured traffic.</div></div>
        </div>

        <div id="oapi-spec-wrap" class="hidden">
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-bold text-gray-300">Generated spec (OpenAPI 3.0)</h3>
            <div class="flex gap-2">
              <button onclick="OpenAPITab.showRaw()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded">Raw</button>
              <button onclick="OpenAPITab.renderSwagger()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded">Swagger UI</button>
              <button onclick="OpenAPITab.copy()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded">Copy</button>
              <button onclick="OpenAPITab.download()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded">Download</button>
              <button onclick="OpenAPITab.openInEditor()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded">Open in Editor</button>
            </div>
          </div>
          <pre id="oapi-spec" class="bg-gray-950 rounded p-3 text-xs text-gray-300 overflow-auto" style="max-height:520px"></pre>
          <div id="oapi-swagger" class="hidden bg-white rounded mt-2"></div>
        </div>
      </div>`;
  },

  _domain() { return (document.getElementById('oapi-domain')?.value || '').trim(); },

  _methodBadge(method) {
    const colors = { GET: 'bg-green-900 text-green-300', POST: 'bg-blue-900 text-blue-300',
      PUT: 'bg-yellow-900 text-yellow-300', DELETE: 'bg-red-900 text-red-300',
      PATCH: 'bg-purple-900 text-purple-300' };
    const c = colors[method] || 'bg-gray-800 text-gray-400';
    return `<span class="px-2 py-0.5 rounded font-mono ${c}">${esc(method)}</span>`;
  },

  async load() {
    const el = document.getElementById('oapi-endpoints');
    el.innerHTML = '<div class="text-gray-500">Scanning…</div>';
    try {
      const resp = await authFetch('/api/openapi/endpoints?domain=' + encodeURIComponent(this._domain()));
      const data = await resp.json();
      if (!data.endpoints.length) {
        el.innerHTML = '<div class="text-gray-500">No HTTP endpoints found in captured traffic for this filter.</div>';
        return;
      }
      el.innerHTML = `<div class="text-gray-500 mb-1">${data.count} endpoint(s)</div>` +
        data.endpoints.map(e => `
          <div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1">
            ${this._methodBadge(e.method)}
            <span class="font-mono text-gray-300 flex-1">${esc(e.path)}</span>
            <span class="text-gray-600">${e.count}×</span>
            <span class="text-gray-600">[${e.statuses.map(esc).join(', ')}]</span>
          </div>`).join('');
    } catch (e) {
      el.innerHTML = '<div class="text-red-400">Error: ' + esc(e.message) + '</div>';
    }
  },

  async generate() {
    const wrap = document.getElementById('oapi-spec-wrap');
    const pre = document.getElementById('oapi-spec');
    const examples = document.getElementById('oapi-examples')?.checked ? 'true' : 'false';
    const fmt = document.getElementById('oapi-format')?.value || 'json';
    try {
      const resp = await authFetch('/api/openapi/spec?domain=' + encodeURIComponent(this._domain()) +
        '&include_examples=' + examples + '&format=' + fmt);
      if (fmt === 'yaml') {
        this.text = await resp.text();
        this.spec = null;
        this.ext = 'yaml';
      } else {
        this.spec = await resp.json();
        const n = Object.keys(this.spec.paths || {}).length;
        if (!n) { Toast.show('No endpoints captured for this filter', 'error'); return; }
        this.text = JSON.stringify(this.spec, null, 2);
        this.ext = 'json';
      }
      pre.textContent = this.text;
      wrap.classList.remove('hidden');
      const n = this.spec ? Object.keys(this.spec.paths || {}).length : null;
      Toast.show(n != null ? `Generated spec with ${n} path(s)` : 'Generated OpenAPI spec (YAML)', 'success');
    } catch (e) {
      Toast.show('Failed to generate: ' + e.message, 'error');
    }
  },

  async copy() {
    if (!this.text) return;
    await copyToClipboard(this.text);
    Toast.show('OpenAPI spec copied', 'success');
  },

  download() {
    if (!this.text) return;
    const ext = this.ext || 'json';
    const mime = ext === 'yaml' ? 'application/yaml' : 'application/json';
    const blob = new Blob([this.text], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'openapi.' + ext;
    a.click();
    URL.revokeObjectURL(a.href);
  },

  showRaw() {
    document.getElementById('oapi-swagger')?.classList.add('hidden');
    document.getElementById('oapi-spec')?.classList.remove('hidden');
  },

  renderSwagger() {
    if (typeof SwaggerUIBundle === 'undefined') {
      Toast.show('Swagger UI failed to load (offline?)', 'error');
      return;
    }
    const examples = document.getElementById('oapi-examples')?.checked ? 'true' : 'false';
    // Swagger UI fetches JSON from our endpoint itself (always JSON, regardless
    // of the download-format selector).
    const url = '/api/openapi/spec?domain=' + encodeURIComponent(this._domain()) +
      '&include_examples=' + examples;
    document.getElementById('oapi-spec').classList.add('hidden');
    const container = document.getElementById('oapi-swagger');
    container.classList.remove('hidden');
    container.innerHTML = '';
    SwaggerUIBundle({
      url,
      dom_id: '#oapi-swagger',
      deepLinking: false,
      presets: [SwaggerUIBundle.presets.apis],
      layout: 'BaseLayout',
    });
  },

  openInEditor() {
    window.open('https://editor.swagger.io/', '_blank');
    Toast.show('Paste the downloaded/copied spec into the editor', 'info');
  },
};

// Authorization / IDOR tester — replay one request under multiple auth
// profiles and diff the responses to flag broken access control.
const AuthzTab = {
  profiles: [
    { name: 'high-priv', headers: '{"Authorization": "Bearer HIGH_PRIV_TOKEN"}' },
    { name: 'low-priv', headers: '{"Authorization": "Bearer LOW_PRIV_TOKEN"}' },
  ],
  lastResult: null,

  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">Authorization / IDOR Tester</h2>
          <p class="text-xs text-gray-500">Replay one request under multiple auth profiles and diff the responses. A profile that gets a 2xx response effectively identical to the baseline (authorized) identity is flagged as possible broken access control.</p>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Method</label>
            <select id="authz-method" class="bg-gray-900 text-gray-200 text-xs px-2 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
              ${['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => `<option value="${m}">${m}</option>`).join('')}
            </select>
          </div>
          <div class="flex flex-col flex-1" style="min-width:320px">
            <label class="text-xs text-gray-400 mb-1">URL</label>
            <input id="authz-url" class="bg-gray-900 text-gray-200 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder="https://api.example.com/users/42">
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Base headers (JSON)</label>
            <textarea id="authz-headers" rows="4" class="bg-gray-900 text-gray-200 text-xs font-mono px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder='{"Accept": "application/json"}'>{}</textarea>
          </div>
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Body</label>
            <textarea id="authz-body" rows="4" class="bg-gray-900 text-gray-200 text-xs font-mono px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder=""></textarea>
          </div>
        </div>

        <div>
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-bold text-gray-300">Auth profiles</h3>
            <button onclick="AuthzTab.addProfile()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded">+ Add profile</button>
          </div>
          <div id="authz-profiles" class="space-y-2"></div>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Baseline (authorized / high-priv) profile</label>
            <select id="authz-baseline" class="bg-gray-900 text-gray-200 text-xs px-2 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" style="min-width:200px"></select>
          </div>
          <button onclick="AuthzTab.run()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded">Run test</button>
        </div>

        <div id="authz-analysis" class="hidden text-xs rounded p-3 border"></div>

        <div id="authz-results-wrap" class="hidden">
          <h3 class="text-sm font-bold text-gray-300 mb-2">Results</h3>
          <table class="w-full text-xs text-left">
            <thead class="text-gray-400 border-b border-gray-700">
              <tr>
                <th class="py-2 pr-3">Profile</th>
                <th class="py-2 pr-3">Status</th>
                <th class="py-2 pr-3">Length</th>
                <th class="py-2 pr-3">Duration</th>
                <th class="py-2 pr-3">Flag</th>
              </tr>
            </thead>
            <tbody id="authz-results"></tbody>
          </table>
        </div>
      </div>`;
  },

  load() {
    this._renderProfiles();
  },

  _renderProfiles() {
    const wrap = document.getElementById('authz-profiles');
    if (!wrap) return;
    wrap.innerHTML = this.profiles.map((p, i) => `
      <div class="flex items-start gap-2">
        <input value="${esc(p.name)}" oninput="AuthzTab.updateProfile(${i}, 'name', this.value)"
          class="bg-gray-900 text-gray-200 text-xs px-2 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder="profile name" style="width:160px">
        <input value="${esc(p.headers)}" oninput="AuthzTab.updateProfile(${i}, 'headers', this.value)"
          class="bg-gray-900 text-gray-200 text-xs font-mono px-2 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500 flex-1" placeholder='{"Authorization": "Bearer ..."}'>
        <button onclick="AuthzTab.removeProfile(${i})" class="bg-red-900 hover:bg-red-800 text-red-200 text-xs px-2 py-2 rounded">✕</button>
      </div>`).join('');
    this._renderBaselineOptions();
  },

  _renderBaselineOptions() {
    const sel = document.getElementById('authz-baseline');
    if (!sel) return;
    const cur = sel.value;
    sel.innerHTML = this.profiles.map(p => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join('');
    if (this.profiles.some(p => p.name === cur)) sel.value = cur;
  },

  addProfile() {
    this.profiles.push({ name: 'profile-' + (this.profiles.length + 1), headers: '{}' });
    this._renderProfiles();
  },

  removeProfile(i) {
    this.profiles.splice(i, 1);
    this._renderProfiles();
  },

  updateProfile(i, field, value) {
    if (this.profiles[i]) {
      this.profiles[i][field] = value;
      if (field === 'name') this._renderBaselineOptions();
    }
  },

  _parseJSON(text, label) {
    const t = (text || '').trim();
    if (!t) return {};
    try {
      const v = JSON.parse(t);
      if (v && typeof v === 'object' && !Array.isArray(v)) return v;
      throw new Error('must be a JSON object');
    } catch (e) {
      throw new Error(`${label}: invalid JSON (${e.message})`);
    }
  },

  async run() {
    const analysisEl = document.getElementById('authz-analysis');
    const wrap = document.getElementById('authz-results-wrap');
    const tbody = document.getElementById('authz-results');

    let payload;
    try {
      const profiles = this.profiles.map(p => ({
        name: p.name,
        headers: this._parseJSON(p.headers, `Profile "${p.name}" headers`),
      }));
      payload = {
        method: document.getElementById('authz-method').value,
        url: document.getElementById('authz-url').value.trim(),
        headers: this._parseJSON(document.getElementById('authz-headers').value, 'Base headers'),
        body: document.getElementById('authz-body').value,
        profiles,
        baseline: document.getElementById('authz-baseline').value,
      };
    } catch (e) {
      Toast.show(e.message, 'error');
      return;
    }

    if (!payload.url) { Toast.show('URL is required', 'error'); return; }
    if (!payload.profiles.length) { Toast.show('Add at least one profile', 'error'); return; }

    try {
      const resp = await authFetch('/api/authz/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || ('HTTP ' + resp.status));
      }
      const data = await resp.json();
      this.lastResult = data;

      const flagged = new Set(data.flagged || []);
      tbody.innerHTML = (data.results || []).map(r => {
        const isFlagged = flagged.has(r.name);
        const isBaseline = r.name === data.baseline;
        const status = r.error
          ? `<span class="text-amber-400" title="${esc(r.error)}">ERR</span>`
          : `<span class="${r.status_code >= 200 && r.status_code < 300 ? 'text-green-400' : 'text-gray-300'}">${esc(String(r.status_code))}</span>`;
        const flagCell = isFlagged
          ? '<span class="px-2 py-0.5 rounded bg-red-900 text-red-300 font-bold">BROKEN ACCESS</span>'
          : (isBaseline ? '<span class="text-gray-500">baseline</span>' : '<span class="text-gray-600">ok</span>');
        return `
          <tr class="border-b border-gray-800 ${isFlagged ? 'bg-red-950/40' : ''}">
            <td class="py-2 pr-3 font-mono text-gray-200">${esc(r.name)}</td>
            <td class="py-2 pr-3">${status}</td>
            <td class="py-2 pr-3 text-gray-300">${esc(String(r.length))}</td>
            <td class="py-2 pr-3 text-gray-500">${r.duration_ms == null ? '—' : esc(String(r.duration_ms)) + 'ms'}</td>
            <td class="py-2 pr-3">${flagCell}</td>
          </tr>`;
      }).join('');
      wrap.classList.remove('hidden');

      analysisEl.className = 'text-xs rounded p-3 border ' +
        (flagged.size ? 'bg-red-950/50 border-red-800 text-red-200' : 'bg-gray-900 border-gray-700 text-gray-300');
      analysisEl.textContent = data.analysis || '';
      analysisEl.classList.remove('hidden');

      Toast.show(flagged.size ? `${flagged.size} profile(s) flagged` : 'No broken access control detected',
        flagged.size ? 'error' : 'success');
    } catch (e) {
      Toast.show('Test failed: ' + e.message, 'error');
    }
  },
};

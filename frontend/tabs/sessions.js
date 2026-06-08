// Capture Sessions — save the current in-memory flows to disk and restore them later.
const SessionsTab = {
  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">Capture Sessions</h2>
          <p class="text-xs text-gray-500">Flows are kept in memory and lost on restart. Save a named snapshot of the current traffic and load it back later.</p>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Session name</label>
            <input id="sess-name" class="bg-gray-900 text-gray-200 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder="e.g. login-flow" style="width:280px">
          </div>
          <button onclick="SessionsTab.save()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-2 rounded">Save current flows</button>
          <button onclick="SessionsTab.load()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-2 rounded">Refresh</button>
        </div>

        <div>
          <h3 class="text-sm font-bold text-gray-300 mb-2">Saved sessions</h3>
          <div id="sess-list" class="space-y-1 text-xs"><div class="text-gray-500">Loading…</div></div>
        </div>
      </div>`;
  },

  _fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  },

  _fmtTime(ts) {
    try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return ''; }
  },

  async load() {
    const el = document.getElementById('sess-list');
    if (!el) return;
    el.innerHTML = '<div class="text-gray-500">Loading…</div>';
    try {
      const resp = await authFetch('/api/sessions');
      const sessions = await resp.json();
      if (!sessions.length) {
        el.innerHTML = '<div class="text-gray-500">No saved sessions yet.</div>';
        return;
      }
      el.innerHTML = sessions.map(s => `
        <div class="flex items-center gap-2 bg-gray-900 rounded px-3 py-2">
          <span class="font-mono text-gray-200 flex-1">${esc(s.name)}</span>
          <span class="text-gray-500">${s.count} flow(s)</span>
          <span class="text-gray-600">${esc(this._fmtSize(s.size_bytes))}</span>
          <span class="text-gray-600">${esc(this._fmtTime(s.modified))}</span>
          <button onclick="SessionsTab.loadSession('${esc(s.name)}')" class="bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-1 rounded">Load</button>
          <button onclick="SessionsTab.deleteSession('${esc(s.name)}')" class="bg-red-700 hover:bg-red-600 text-white px-2 py-1 rounded">Delete</button>
        </div>`).join('');
    } catch (e) {
      el.innerHTML = '<div class="text-red-400">Error: ' + esc(e.message) + '</div>';
    }
  },

  async save() {
    const name = (document.getElementById('sess-name')?.value || '').trim();
    if (!name) { Toast.show('Enter a session name', 'error'); return; }
    try {
      const resp = await authFetch('/api/sessions/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      if (!resp.ok) { Toast.show('Save failed: ' + resp.status, 'error'); return; }
      const data = await resp.json();
      Toast.show(`Saved ${data.count} flow(s) as "${data.name}"`, 'success');
      this.load();
    } catch (e) {
      Toast.show('Save failed: ' + e.message, 'error');
    }
  },

  async loadSession(name) {
    try {
      const resp = await authFetch('/api/sessions/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, clear: true }),
      });
      if (!resp.ok) { Toast.show('Load failed: ' + resp.status, 'error'); return; }
      const data = await resp.json();
      Toast.show(`Loaded ${data.loaded} flow(s)`, 'success');
    } catch (e) {
      Toast.show('Load failed: ' + e.message, 'error');
    }
  },

  async deleteSession(name) {
    try {
      const resp = await authFetch('/api/sessions/' + encodeURIComponent(name), { method: 'DELETE' });
      if (!resp.ok) { Toast.show('Delete failed: ' + resp.status, 'error'); return; }
      Toast.show('Session deleted', 'success');
      this.load();
    } catch (e) {
      Toast.show('Delete failed: ' + e.message, 'error');
    }
  },
};

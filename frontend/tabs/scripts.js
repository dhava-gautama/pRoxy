// Custom mitmproxy addon scripts — upload/list/delete.
const ScriptsTab = {
  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">Custom Addon Scripts</h2>
          <p class="text-xs text-gray-500">Upload a mitmproxy addon (<code>.py</code>) to run custom request/response logic. Files are loaded at proxy startup with full hooks + hot-reload.</p>
        </div>

        <div class="bg-gray-900 rounded p-3 text-xs text-gray-400 space-y-1">
          <div>• <b>Add a script:</b> upload below (or drop a <code>.py</code> in the <code id="scr-dir" class="text-gray-300">scripts/</code> dir), then <b>restart the proxy</b> to load it.</div>
          <div>• Editing an already-loaded script <b>hot-reloads</b> automatically.</div>
          <div>• Files starting with <code>_</code> are ignored (use for templates).</div>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Upload addon (.py)</label>
            <input id="scr-file" type="file" accept=".py" class="text-xs text-gray-300">
          </div>
          <button onclick="ScriptsTab.upload()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-2 rounded">Upload</button>
          <button onclick="ScriptsTab.showSample()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-2 rounded">Show template</button>
          <button onclick="ScriptsTab.load()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-2 rounded">Refresh</button>
        </div>

        <pre id="scr-sample" class="hidden bg-gray-950 rounded p-3 text-xs text-gray-300 overflow-auto" style="max-height:240px"></pre>

        <div>
          <h3 class="text-sm font-bold text-gray-300 mb-2">Installed scripts</h3>
          <div id="scr-list" class="space-y-1 text-xs"><div class="text-gray-500">Loading…</div></div>
        </div>
      </div>`;
  },

  async load() {
    const el = document.getElementById('scr-list');
    try {
      const resp = await authFetch('/api/scripts');
      if (!resp.ok) { el.innerHTML = '<div class="text-red-400">Failed to load scripts</div>'; return; }
      const data = await resp.json();
      const dir = document.getElementById('scr-dir'); if (dir) dir.textContent = data.scripts_dir;
      if (!data.scripts.length) {
        el.innerHTML = '<div class="text-gray-500">No scripts yet. Upload one above.</div>';
        return;
      }
      el.innerHTML = data.scripts.map(s => {
        const badge = s.ignored
          ? '<span class="px-2 py-0.5 rounded bg-gray-800 text-gray-500">ignored</span>'
          : (s.loaded
              ? '<span class="px-2 py-0.5 rounded bg-green-900 text-green-300">loaded</span>'
              : '<span class="px-2 py-0.5 rounded bg-yellow-900 text-yellow-300">restart to load</span>');
        return `<div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1">
            ${badge}
            <span class="font-mono text-gray-300 flex-1">${esc(s.name)}</span>
            <span class="text-gray-600">${s.size} B</span>
            <button onclick="ScriptsTab.del('${esc(s.name)}')" class="text-red-400 hover:text-red-300">Delete</button>
          </div>`;
      }).join('');
    } catch (e) {
      el.innerHTML = '<div class="text-red-400">Error: ' + esc(e.message) + '</div>';
    }
  },

  async upload() {
    const input = document.getElementById('scr-file');
    const f = input?.files?.[0];
    if (!f) { Toast.show('Choose a .py file first', 'error'); return; }
    const fd = new FormData();
    fd.append('file', f);
    try {
      const resp = await authFetch('/api/scripts/upload', { method: 'POST', body: fd });
      const data = await resp.json();
      if (!resp.ok) { Toast.show(data.detail || 'Upload failed', 'error'); return; }
      Toast.show(`Uploaded ${data.name} — restart proxy to load`, 'success');
      input.value = '';
      this.load();
    } catch (e) {
      Toast.show('Upload failed: ' + e.message, 'error');
    }
  },

  async del(name) {
    if (!confirm(`Delete ${name}?`)) return;
    try {
      const resp = await authFetch('/api/scripts/' + encodeURIComponent(name), { method: 'DELETE' });
      if (!resp.ok) { Toast.show('Delete failed', 'error'); return; }
      Toast.show(`Deleted ${name} — restart proxy to apply`, 'success');
      this.load();
    } catch (e) {
      Toast.show('Delete failed: ' + e.message, 'error');
    }
  },

  async showSample() {
    const pre = document.getElementById('scr-sample');
    try {
      const resp = await authFetch('/api/scripts/sample');
      const data = await resp.json();
      pre.textContent = `# ${data.filename}\n\n${data.content}`;
      pre.classList.toggle('hidden');
    } catch (e) {
      Toast.show('Could not load template', 'error');
    }
  },
};

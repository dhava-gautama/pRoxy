// HAR / Flow import — load captured traffic from a HAR archive or pRoxy flow export.
const ImporterTab = {
  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">Import HAR / Flows</h2>
          <p class="text-xs text-gray-500">Load a HAR archive (browser/DevTools export) or a pRoxy flow list. Imported entries appear live in Traffic.</p>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Choose file (.har / .json)</label>
            <input id="import-file" type="file" accept=".har,.json" class="text-xs text-gray-300 file:bg-gray-700 file:hover:bg-gray-600 file:text-white file:text-xs file:px-3 file:py-2 file:rounded file:border-0 file:mr-3">
          </div>
          <button onclick="ImporterTab.importFile()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-2 rounded">Import file</button>
        </div>

        <div>
          <label class="text-xs text-gray-400 mb-1 block">Or paste JSON / HAR</label>
          <textarea id="import-paste" rows="8" class="w-full bg-gray-900 text-gray-200 text-xs font-mono px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder='{"log": {"entries": [...]}}  or  [{"id":"f1","timestamp":0,...}]'></textarea>
          <button onclick="ImporterTab.importPaste()" class="mt-2 bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-2 rounded">Import pasted text</button>
        </div>

        <div>
          <h3 class="text-sm font-bold text-gray-300 mb-2">Result</h3>
          <div id="import-result" class="text-xs text-gray-500">No import yet.</div>
        </div>
      </div>`;
  },

  load() {},

  async importFile() {
    const input = document.getElementById('import-file');
    const file = input?.files?.[0];
    if (!file) { Toast.show('Choose a file first', 'error'); return; }
    try {
      const text = await file.text();
      await this._send(text);
    } catch (e) {
      Toast.show('Failed to read file: ' + e.message, 'error');
    }
  },

  async importPaste() {
    const text = (document.getElementById('import-paste')?.value || '').trim();
    if (!text) { Toast.show('Paste some JSON first', 'error'); return; }
    await this._send(text);
  },

  async _send(text) {
    const el = document.getElementById('import-result');
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      Toast.show('Invalid JSON: ' + e.message, 'error');
      el.innerHTML = '<div class="text-red-400">Invalid JSON: ' + esc(e.message) + '</div>';
      return;
    }
    el.innerHTML = '<div class="text-gray-500">Importing…</div>';
    try {
      const resp = await authFetch('/api/import/har', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      if (!resp.ok) {
        let detail = 'HTTP ' + resp.status;
        try { detail = (await resp.json()).detail || detail; } catch (_) {}
        Toast.show('Import failed: ' + detail, 'error');
        el.innerHTML = '<div class="text-red-400">Import failed: ' + esc(detail) + '</div>';
        return;
      }
      const data = await resp.json();
      Toast.show(`Imported ${data.imported} flow(s)`, 'success');
      const errs = (data.errors || []);
      el.innerHTML =
        `<div class="text-green-400 mb-1">Imported ${data.imported} flow(s)` +
        (errs.length ? `, ${errs.length} skipped` : '') + '.</div>' +
        (errs.length
          ? `<ul class="text-amber-400 list-disc pl-5 space-y-0.5">` +
            errs.map(e => `<li>${esc(e)}</li>`).join('') + `</ul>`
          : '');
    } catch (e) {
      Toast.show('Import failed: ' + e.message, 'error');
      el.innerHTML = '<div class="text-red-400">Import failed: ' + esc(e.message) + '</div>';
    }
  },
};

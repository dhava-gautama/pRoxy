// Intercept tab: enhanced breakpoint editor with headers table + JSON formatting
window.InterceptTab = {
  queue: [],
  selectedKey: null,
  pollTimer: null,

  render() {
    return `
      <div class="split-pane">
        <div class="flow-list w-1/2 min-w-[300px]" id="intercept-list">
          <div class="flex items-center justify-between px-3 py-2 bg-gray-900 border-b border-gray-800 sticky top-0 z-10">
            <h3 class="text-sm font-bold text-gray-400">Intercepted</h3>
            <span class="text-xs text-gray-500" id="intercept-count">0 queued</span>
          </div>
          <div id="intercept-rows"></div>
        </div>
        <div class="flow-detail w-1/2 p-4" id="intercept-detail">
          <div class="text-gray-600 text-center">Enable intercept mode in Rules tab</div>
        </div>
      </div>`;
  },

  start() {
    this.poll();
    this.pollTimer = setInterval(() => this.poll(), 1000);
  },

  stop() {
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
  },

  async poll() {
    try {
      const resp = await authFetch('/api/intercept/queue');
      if (!resp.ok) return;
      this.queue = await resp.json();
      this.renderList();
    } catch (e) { /* ignore */ }
  },

  renderList() {
    const container = document.getElementById('intercept-rows');
    if (!container) return;
    document.getElementById('intercept-count').textContent = this.queue.length + ' queued';
    container.innerHTML = this.queue.length === 0
      ? '<div class="p-4 text-gray-600 text-xs text-center">No intercepted flows</div>'
      : this.queue.map(item => {
        const f = item.flow_record;
        const key = item.id + ':' + item.phase;
        const sel = key === this.selectedKey ? 'bg-gray-800' : 'hover:bg-gray-900';
        const phaseColor = item.phase === 'response' ? 'text-green-400' : 'text-yellow-400';
        const phaseBadge = item.phase === 'response'
          ? '<span class="badge bg-green-900 text-green-300">RESP</span>'
          : '<span class="badge bg-yellow-900 text-yellow-300">REQ</span>';
        return `
          <div class="flex items-center gap-2 px-3 py-1.5 cursor-pointer border-b border-gray-800/50 ${sel} text-xs"
               onclick="InterceptTab.select('${esc(item.id)}', '${esc(item.phase)}')">
            ${phaseBadge}
            <span class="w-14 ${phaseColor} shrink-0">${esc(f.method)}</span>
            <span class="text-gray-400 shrink-0">${esc(f.host)}</span>
            <span class="text-gray-500 truncate">${esc(f.path)}</span>
            ${f.status_code ? `<span class="text-gray-500">${esc(f.status_code)}</span>` : ''}
          </div>`;
      }).join('');
  },

  select(id, phase) {
    this.selectedKey = id + ':' + phase;
    const item = this.queue.find(q => q.id === id && q.phase === phase);
    if (!item) return;
    const f = item.flow_record;
    this.renderList();

    const isResponse = phase === 'response';
    const headersObj = isResponse ? (f.response_headers || {}) : (f.request_headers || {});
    const body = isResponse ? (f.response_body || '') : (f.request_body || '');
    const headersLabel = isResponse ? 'Response Headers' : 'Request Headers';
    const bodyLabel = isResponse ? 'Response Body' : 'Request Body';

    // Try to format JSON body
    let formattedBody = body;
    let isJson = false;
    const ct = isResponse
      ? (f.response_content_type || '').toLowerCase()
      : (f.request_content_type || '').toLowerCase();
    if (ct.includes('json')) {
      try {
        formattedBody = JSON.stringify(JSON.parse(body), null, 2);
        isJson = true;
      } catch {}
    }

    // Build headers table
    const headerRows = Object.entries(headersObj).map(([k, v], i) =>
      `<tr class="border-b border-gray-800">
        <td class="py-1 pr-2"><input type="text" value="${esc(k)}" data-hdr-key="${i}"
          class="w-full bg-transparent text-indigo-400 text-xs focus:outline-none focus:bg-gray-800 px-1 rounded"></td>
        <td class="py-1 pr-1"><input type="text" value="${esc(v)}" data-hdr-val="${i}"
          class="w-full bg-transparent text-gray-300 text-xs focus:outline-none focus:bg-gray-800 px-1 rounded"></td>
        <td class="py-1 w-6"><button onclick="this.closest('tr').remove()" class="text-red-500 hover:text-red-400 text-xs">x</button></td>
      </tr>`
    ).join('');

    document.getElementById('intercept-detail').innerHTML = `
      <div class="space-y-4">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="font-bold ${isResponse ? 'text-green-400' : 'text-yellow-400'}">${isResponse ? 'RESPONSE' : 'REQUEST'}</span>
          <span class="font-bold text-white">${esc(f.method)}</span>
          ${f.status_code ? `<span class="text-gray-400">${esc(f.status_code)}</span>` : ''}
          <span class="text-gray-300 break-all text-xs">${esc(f.url)}</span>
        </div>

        <div>
          <div class="flex items-center justify-between mb-1">
            <h3 class="text-xs font-bold text-gray-400 uppercase">${headersLabel}</h3>
            <button onclick="InterceptTab.addHeader()" class="text-xs text-indigo-400 hover:text-indigo-300">+ Add Header</button>
          </div>
          <div class="bg-gray-900 rounded border border-gray-700 overflow-hidden">
            <table class="w-full text-xs" id="intercept-headers-table">
              <tbody>${headerRows}</tbody>
            </table>
          </div>
        </div>

        <div>
          <div class="flex items-center justify-between mb-1">
            <h3 class="text-xs font-bold text-gray-400 uppercase">${bodyLabel}${isJson ? ' <span class="text-green-400">(JSON)</span>' : ''}</h3>
            ${isJson ? '<button onclick="InterceptTab.formatBody()" class="text-xs text-indigo-400 hover:text-indigo-300">Format</button>' : ''}
          </div>
          <textarea id="intercept-body" rows="12"
            class="w-full bg-gray-900 text-gray-300 text-xs p-3 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"
            spellcheck="false">${esc(formattedBody)}</textarea>
        </div>

        <div class="flex gap-2">
          <button onclick="InterceptTab.forward('${esc(id)}','${esc(phase)}')"
            class="bg-green-700 hover:bg-green-600 text-white text-xs px-4 py-2 rounded flex items-center gap-1">
            Forward <kbd class="ml-1">F</kbd>
          </button>
          <button onclick="InterceptTab.forwardModified('${esc(id)}','${esc(phase)}')"
            class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded flex items-center gap-1">
            Forward Modified <kbd class="ml-1">M</kbd>
          </button>
          <button onclick="InterceptTab.drop('${esc(id)}','${esc(phase)}')"
            class="bg-red-700 hover:bg-red-600 text-white text-xs px-4 py-2 rounded flex items-center gap-1">
            Drop <kbd class="ml-1">D</kbd>
          </button>
          <button onclick="InterceptTab.forwardAll()"
            class="ml-auto bg-gray-700 hover:bg-gray-600 text-white text-xs px-4 py-2 rounded">
            Forward All
          </button>
        </div>
      </div>`;

    // Keyboard shortcuts for intercept
    document.getElementById('intercept-detail').onkeydown = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      if (e.key === 'f') this.forward(id, phase);
      if (e.key === 'm') this.forwardModified(id, phase);
      if (e.key === 'd') this.drop(id, phase);
    };
  },

  addHeader() {
    const tbody = document.querySelector('#intercept-headers-table tbody');
    if (!tbody) return;
    const idx = tbody.children.length;
    const row = document.createElement('tr');
    row.className = 'border-b border-gray-800';
    row.innerHTML = `
      <td class="py-1 pr-2"><input type="text" value="" data-hdr-key="${idx}" placeholder="Header-Name"
        class="w-full bg-transparent text-indigo-400 text-xs focus:outline-none focus:bg-gray-800 px-1 rounded"></td>
      <td class="py-1 pr-1"><input type="text" value="" data-hdr-val="${idx}" placeholder="value"
        class="w-full bg-transparent text-gray-300 text-xs focus:outline-none focus:bg-gray-800 px-1 rounded"></td>
      <td class="py-1 w-6"><button onclick="this.closest('tr').remove()" class="text-red-500 hover:text-red-400 text-xs">x</button></td>`;
    tbody.appendChild(row);
    row.querySelector('input').focus();
  },

  formatBody() {
    const el = document.getElementById('intercept-body');
    if (!el) return;
    try {
      el.value = JSON.stringify(JSON.parse(el.value), null, 2);
    } catch (e) {
      Toast.show('Invalid JSON', 'error');
    }
  },

  _getHeaders() {
    const headers = {};
    const rows = document.querySelectorAll('#intercept-headers-table tr');
    rows.forEach(row => {
      const keyInput = row.querySelector('[data-hdr-key]');
      const valInput = row.querySelector('[data-hdr-val]');
      if (keyInput && valInput && keyInput.value.trim()) {
        headers[keyInput.value.trim()] = valInput.value;
      }
    });
    return headers;
  },

  async forward(id, phase) {
    await this.resolve(id, phase, 'forward');
  },

  async forwardModified(id, phase) {
    const body = document.getElementById('intercept-body').value;
    const headers = this._getHeaders();
    await this.resolve(id, phase, 'forward', body, headers);
  },

  async drop(id, phase) {
    await this.resolve(id, phase, 'drop');
  },

  async forwardAll() {
    for (const item of [...this.queue]) {
      await this.resolve(item.id, item.phase, 'forward');
    }
  },

  async resolve(id, phase, action, modifiedBody = null, modifiedHeaders = null) {
    try {
      const payload = { action };
      if (modifiedBody !== null) payload.modified_body = modifiedBody;
      if (modifiedHeaders !== null) payload.modified_headers = modifiedHeaders;
      await authFetch(`/api/intercept/${id}/${phase}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      this.selectedKey = null;
      document.getElementById('intercept-detail').innerHTML = '<div class="text-gray-600 text-center">Select a flow</div>';
      Toast.show(`${phase} ${action}ed`, action === 'drop' ? 'warn' : 'success');
      this.poll();
    } catch (e) {
      Toast.show('Failed to resolve', 'error');
    }
  }
};

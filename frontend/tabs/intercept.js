// Intercept tab: view queued requests/responses, forward/drop/edit
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
      const resp = await fetch('/api/intercept/queue');
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
               onclick="InterceptTab.select('${item.id}', '${item.phase}')">
            ${phaseBadge}
            <span class="w-14 ${phaseColor} shrink-0">${f.method}</span>
            <span class="text-gray-400 shrink-0">${f.host}</span>
            <span class="text-gray-500 truncate">${f.path}</span>
            ${f.status_code ? `<span class="text-gray-500">${f.status_code}</span>` : ''}
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

    document.getElementById('intercept-detail').innerHTML = `
      <div class="space-y-4">
        <div class="flex items-center gap-2">
          <span class="font-bold ${isResponse ? 'text-green-400' : 'text-yellow-400'}">${isResponse ? 'RESPONSE' : 'REQUEST'}</span>
          <span class="font-bold text-white">${f.method}</span>
          ${f.status_code ? `<span class="text-gray-400">${f.status_code}</span>` : ''}
          <span class="text-gray-300 break-all">${f.url}</span>
        </div>

        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">${headersLabel}</h3>
          <textarea id="intercept-headers" rows="8"
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"
          >${Object.entries(headersObj).map(([k,v]) => k + ': ' + v).join('\n')}</textarea>
        </div>

        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">${bodyLabel}</h3>
          <textarea id="intercept-body" rows="8"
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"
          >${body}</textarea>
        </div>

        <div class="flex gap-2">
          <button onclick="InterceptTab.forward('${id}','${phase}')" class="bg-green-700 hover:bg-green-600 text-white text-xs px-4 py-2 rounded">Forward</button>
          <button onclick="InterceptTab.forwardModified('${id}','${phase}')" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded">Forward (Modified)</button>
          <button onclick="InterceptTab.drop('${id}','${phase}')" class="bg-red-700 hover:bg-red-600 text-white text-xs px-4 py-2 rounded">Drop</button>
        </div>
      </div>`;
  },

  async forward(id, phase) {
    await this.resolve(id, phase, 'forward');
  },

  async forwardModified(id, phase) {
    const headersText = document.getElementById('intercept-headers').value;
    const body = document.getElementById('intercept-body').value;
    const headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    await this.resolve(id, phase, 'forward', body, headers);
  },

  async drop(id, phase) {
    await this.resolve(id, phase, 'drop');
  },

  async resolve(id, phase, action, modifiedBody = null, modifiedHeaders = null) {
    try {
      const payload = { action };
      if (modifiedBody !== null) payload.modified_body = modifiedBody;
      if (modifiedHeaders !== null) payload.modified_headers = modifiedHeaders;
      await fetch(`/api/intercept/${id}/${phase}`, {
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

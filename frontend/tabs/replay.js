// Replay tab: send/resend HTTP requests (Repeater)
window.ReplayTab = {
  history: [],

  render() {
    return `
      <div class="flex h-[calc(100vh-56px)]">
        <!-- Request panel -->
        <div class="w-1/2 p-4 space-y-3 overflow-y-auto border-r border-gray-800">
          <h2 class="text-lg font-bold text-white">Replay</h2>
          <div class="flex gap-2">
            <select id="replay-method" class="bg-gray-800 text-gray-300 text-xs px-2 py-2 rounded border border-gray-700">
              <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option>
              <option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
            </select>
            <input id="replay-url" type="text" placeholder="https://example.com/api/endpoint"
              class="flex-1 bg-gray-800 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Headers</h3>
            <textarea id="replay-headers" rows="6" placeholder="Content-Type: application/json\nAuthorization: Bearer ..."
              class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
          </div>
          <div>
            <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Body</h3>
            <textarea id="replay-body" rows="8" placeholder='{"key": "value"}'
              class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
          </div>
          <div class="flex gap-2">
            <button onclick="ReplayTab.send()" id="replay-send-btn" class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-6 py-2 rounded">Send</button>
            <button onclick="ReplayTab.clear()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-4 py-2 rounded">Clear</button>
          </div>

          <!-- History -->
          <div class="mt-4">
            <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">History</h3>
            <div id="replay-history" class="space-y-1 max-h-48 overflow-y-auto"></div>
          </div>
        </div>

        <!-- Response panel -->
        <div class="w-1/2 p-4 overflow-y-auto">
          <h3 class="text-sm font-bold text-gray-400 mb-2">Response</h3>
          <div id="replay-response" class="text-gray-600 text-xs">Send a request to see the response</div>
        </div>
      </div>`;
  },

  load() {
    // Check for prefill from traffic tab
    if (window._replayPrefill) {
      const p = window._replayPrefill;
      document.getElementById('replay-method').value = p.method || 'GET';
      document.getElementById('replay-url').value = p.url || '';
      document.getElementById('replay-headers').value = Object.entries(p.headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');
      document.getElementById('replay-body').value = p.body || '';
      window._replayPrefill = null;
    }
    this.renderHistory();
  },

  async send() {
    const method = document.getElementById('replay-method').value;
    const url = document.getElementById('replay-url').value;
    if (!url) { Toast.show('URL is required', 'warn'); return; }

    const headersText = document.getElementById('replay-headers').value;
    const body = document.getElementById('replay-body').value;
    const headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });

    const btn = document.getElementById('replay-send-btn');
    btn.textContent = 'Sending...';
    btn.disabled = true;

    try {
      const resp = await fetch('/api/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, url, headers, body })
      });
      const data = await resp.json();

      if (!resp.ok) {
        document.getElementById('replay-response').innerHTML = `<div class="text-red-400">${esc(data.detail || 'Request failed')}</div>`;
        return;
      }

      // Add to history
      this.history.unshift({ method, url, status: data.status_code, duration: data.duration_ms });
      if (this.history.length > 50) this.history.pop();
      this.renderHistory();

      // Render response
      const respHeaders = Object.entries(data.headers || {}).map(([k,v]) =>
        `<span class="text-green-400">${esc(k)}</span>: <span class="text-gray-300">${esc(v)}</span>`
      ).join('<br>');

      const statusCls = data.status_code < 300 ? 'text-green-400' : data.status_code < 400 ? 'text-blue-400' : data.status_code < 500 ? 'text-yellow-400' : 'text-red-400';

      document.getElementById('replay-response').innerHTML = `
        <div class="space-y-3">
          <div class="flex items-center gap-3">
            <span class="${statusCls} font-bold">${data.status_code} ${data.reason || ''}</span>
            <span class="text-gray-500 text-xs">${data.duration_ms}ms</span>
          </div>
          <div>
            <h4 class="text-xs font-bold text-gray-400 uppercase mb-1">Headers</h4>
            <div class="bg-gray-900 rounded p-2 text-xs">${respHeaders}</div>
          </div>
          <div>
            <h4 class="text-xs font-bold text-gray-400 uppercase mb-1">Body</h4>
            <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${esc(data.body || '')}</pre>
          </div>
        </div>`;
    } catch (e) {
      document.getElementById('replay-response').innerHTML = `<div class="text-red-400">Error: ${esc(e.message)}</div>`;
    } finally {
      btn.textContent = 'Send';
      btn.disabled = false;
    }
  },

  clear() {
    document.getElementById('replay-method').value = 'GET';
    document.getElementById('replay-url').value = '';
    document.getElementById('replay-headers').value = '';
    document.getElementById('replay-body').value = '';
    document.getElementById('replay-response').innerHTML = '<span class="text-gray-600">Send a request to see the response</span>';
  },

  renderHistory() {
    const el = document.getElementById('replay-history');
    if (!el) return;
    el.innerHTML = this.history.length === 0
      ? '<div class="text-gray-600 text-xs">No history yet</div>'
      : this.history.map((h, i) => `
        <div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1 text-xs cursor-pointer hover:bg-gray-800"
             onclick="ReplayTab.loadFromHistory(${i})">
          <span class="text-gray-500 w-10">${h.method}</span>
          <span class="${h.status < 300 ? 'text-green-400' : h.status < 500 ? 'text-yellow-400' : 'text-red-400'}">${h.status}</span>
          <span class="text-gray-400 truncate">${h.url}</span>
          <span class="ml-auto text-gray-600">${h.duration}ms</span>
        </div>
      `).join('');
  },

  loadFromHistory(i) {
    // Just fill URL and method from history, user can re-send
    const h = this.history[i];
    if (!h) return;
    document.getElementById('replay-method').value = h.method;
    document.getElementById('replay-url').value = h.url;
  }
};

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

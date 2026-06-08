// Encoder/Decoder Tools tab + SSL Bypass Profiles + Stress Test
window.ToolsTab = {
  sslProfiles: [],
  stressRunning: false,

  render() {
    return `
      <div class="max-w-5xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <!-- Stress Test -->
        <div>
          <h2 class="text-lg font-bold text-white mb-3">Stress Test <span class="text-xs text-gray-500 font-normal">(Go-powered)</span></h2>
          <div class="bg-gray-900 rounded p-4 border border-gray-700">
            <div class="grid grid-cols-2 gap-3 mb-3">
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Method</label>
                <select id="stress-method" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
                  <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option>
                </select>
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">URL</label>
                <input id="stress-url" type="text" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500" placeholder="https://example.com/api/endpoint">
              </div>
            </div>
            <div class="grid grid-cols-4 gap-3 mb-3">
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Concurrency</label>
                <input id="stress-concurrency" type="number" value="100" min="1" max="4096" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Total Requests</label>
                <input id="stress-total" type="number" value="1000" min="1" max="100000" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Timeout (sec)</label>
                <input id="stress-timeout" type="number" value="10" min="1" max="60" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
              </div>
              <div class="flex items-end">
                <button id="stress-run-btn" onclick="ToolsTab.runStress()" class="w-full bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1.5 rounded font-bold">Run Stress Test</button>
              </div>
            </div>
            <details class="mb-3">
              <summary class="text-xs text-gray-500 cursor-pointer hover:text-gray-300">Headers & Body</summary>
              <div class="grid grid-cols-2 gap-3 mt-2">
                <div>
                  <label class="text-xs text-gray-400 mb-1 block">Headers (JSON)</label>
                  <textarea id="stress-headers" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono resize-none focus:outline-none focus:border-indigo-500" rows="3" placeholder='{"Content-Type": "application/json"}'></textarea>
                </div>
                <div>
                  <label class="text-xs text-gray-400 mb-1 block">Body</label>
                  <textarea id="stress-body" class="w-full bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono resize-none focus:outline-none focus:border-indigo-500" rows="3" placeholder="Request body..."></textarea>
                </div>
              </div>
            </details>
            <div id="stress-results" class="hidden">
              <div id="stress-progress" class="text-xs text-gray-400 mb-2"></div>
              <div id="stress-summary" class="space-y-2"></div>
            </div>
          </div>
        </div>

        <!-- Encoder/Decoder -->
        <div>
          <h2 class="text-lg font-bold text-white mb-3">Encoder / Decoder Tools</h2>
          <div class="flex flex-wrap gap-2">
            <button onclick="ToolsTab.op('base64enc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Base64 Encode</button>
            <button onclick="ToolsTab.op('base64dec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Base64 Decode</button>
            <button onclick="ToolsTab.op('urlenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">URL Encode</button>
            <button onclick="ToolsTab.op('urldec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">URL Decode</button>
            <button onclick="ToolsTab.op('htmlenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">HTML Encode</button>
            <button onclick="ToolsTab.op('htmldec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">HTML Decode</button>
            <button onclick="ToolsTab.op('hexenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Hex Encode</button>
            <button onclick="ToolsTab.op('hexdec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Hex Decode</button>
            <button onclick="ToolsTab.op('jwt')" class="text-xs bg-indigo-700 hover:bg-indigo-600 text-white px-3 py-1.5 rounded">JWT Decode</button>
            <button onclick="ToolsTab.op('md5')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">MD5</button>
            <button onclick="ToolsTab.op('sha1')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">SHA-1</button>
            <button onclick="ToolsTab.op('sha256')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">SHA-256</button>
          </div>
          <div class="flex gap-4 mt-3" style="height:250px">
            <div class="flex-1 flex flex-col">
              <label class="text-xs text-gray-400 mb-1">Input</label>
              <textarea id="tools-input" class="flex-1 bg-gray-900 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 font-mono resize-none focus:outline-none focus:border-indigo-500" placeholder="Paste text here..."></textarea>
            </div>
            <div class="flex-1 flex flex-col">
              <label class="text-xs text-gray-400 mb-1">Output</label>
              <textarea id="tools-output" class="flex-1 bg-gray-900 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 font-mono resize-none focus:outline-none" readonly></textarea>
            </div>
          </div>
        </div>

        <!-- SSL Bypass Profiles -->
        <div>
          <h2 class="text-lg font-bold text-white mb-3">SSL Pinning Bypass Profiles</h2>
          <div id="ssl-profiles" class="space-y-3">
            <div class="text-xs text-gray-500">Loading profiles...</div>
          </div>
        </div>
      </div>`;
  },

  async loadSSLProfiles() {
    try {
      const resp = await authFetch('/api/settings/ssl-profiles');
      if (!resp.ok) {
        const el = document.getElementById('ssl-profiles');
        if (el) el.innerHTML = '<div class="text-xs text-red-400">Failed to load profiles (HTTP ' + resp.status + '). Restart the server.</div>';
        return;
      }
      this.sslProfiles = await resp.json();
      this._renderSSLProfiles();
    } catch (e) {
      const el = document.getElementById('ssl-profiles');
      if (el) el.innerHTML = '<div class="text-xs text-red-400">Error loading profiles: ' + esc(e.message) + '</div>';
    }
  },

  _renderSSLProfiles() {
    const el = document.getElementById('ssl-profiles');
    if (!el) return;
    el.innerHTML = this.sslProfiles.map((p, i) => `
      <div class="bg-gray-900 rounded p-4 border border-gray-700">
        <div class="flex items-center justify-between mb-2">
          <div>
            <h3 class="text-sm font-bold text-white">${esc(p.name)}</h3>
            <p class="text-xs text-gray-500">${esc(p.description)}</p>
          </div>
          <button onclick="ToolsTab.applySSLProfile(${i})" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded">Apply Settings</button>
        </div>
        <div class="flex gap-2 text-xs mb-2">
          ${Object.entries(p.settings).map(([k,v]) =>
            `<span class="px-2 py-0.5 rounded ${v ? 'bg-green-900 text-green-300' : 'bg-gray-800 text-gray-500'}">${k.replace(/_/g, ' ')}</span>`
          ).join('')}
        </div>
        ${p.frida_script ? `
        <details>
          <summary class="text-xs text-indigo-400 cursor-pointer hover:text-indigo-300">Frida Script</summary>
          <div class="mt-2 relative">
            <pre class="bg-gray-950 rounded p-3 text-xs text-gray-300 overflow-x-auto" style="max-height:300px">${esc(p.frida_script)}</pre>
            <button onclick="ToolsTab.copyFridaScript(${i})" class="absolute top-2 right-2 text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded">Copy</button>
          </div>
        </details>` : ''}
      </div>
    `).join('');
  },

  async applySSLProfile(idx) {
    try {
      const resp = await authFetch('/api/settings/ssl-profiles/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index: idx })
      });
      if (!resp.ok) { Toast.show('Failed to apply', 'error'); return; }
      Toast.show('SSL bypass settings applied', 'success');
    } catch { Toast.show('Failed to apply', 'error'); }
  },

  async copyFridaScript(idx) {
    const profile = this.sslProfiles[idx];
    if (!profile || !profile.frida_script) return;
    await copyToClipboard(profile.frida_script);
    Toast.show('Frida script copied', 'success');
  },

  applyPrefill() {
    if (!window._stressPrefill) return;
    const p = window._stressPrefill;
    window._stressPrefill = null;
    setTimeout(() => {
      const methodEl = document.getElementById('stress-method');
      const urlEl = document.getElementById('stress-url');
      const headersEl = document.getElementById('stress-headers');
      const bodyEl = document.getElementById('stress-body');
      if (methodEl) methodEl.value = p.method || 'GET';
      if (urlEl) urlEl.value = p.url || '';
      if (headersEl && p.headers && Object.keys(p.headers).length) {
        headersEl.value = JSON.stringify(p.headers, null, 2);
      }
      if (bodyEl && p.body) bodyEl.value = p.body;
      Toast.show('Request loaded into Stress Test', 'success');
    }, 50);
  },

  async runStress() {
    if (this.stressRunning) return;
    const url = document.getElementById('stress-url').value.trim();
    if (!url) { Toast.show('URL is required', 'error'); return; }

    const method = document.getElementById('stress-method').value;
    const concurrency = parseInt(document.getElementById('stress-concurrency').value) || 100;
    const totalReqs = parseInt(document.getElementById('stress-total').value) || 1000;
    const timeout = parseInt(document.getElementById('stress-timeout').value) || 10;
    const bodyText = document.getElementById('stress-body').value;
    let headers = {};
    try {
      const hdrText = document.getElementById('stress-headers').value.trim();
      if (hdrText) headers = JSON.parse(hdrText);
    } catch { Toast.show('Invalid headers JSON', 'error'); return; }

    this.stressRunning = true;
    const btn = document.getElementById('stress-run-btn');
    btn.textContent = 'Running...';
    btn.disabled = true;
    btn.className = 'w-full bg-gray-600 text-gray-400 text-xs px-3 py-1.5 rounded font-bold cursor-not-allowed';

    const resultsDiv = document.getElementById('stress-results');
    const progressDiv = document.getElementById('stress-progress');
    const summaryDiv = document.getElementById('stress-summary');
    resultsDiv.classList.remove('hidden');
    progressDiv.textContent = `Sending ${totalReqs} requests with ${concurrency} concurrent workers...`;
    summaryDiv.innerHTML = '<div class="text-xs text-gray-500">Waiting for results...</div>';

    try {
      const resp = await authFetch('/api/stress', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method, url, headers, body: bodyText,
          concurrency, total_requests: totalReqs, timeout_sec: timeout,
          follow_redirects: true, insecure: true,
        }),
      });
      if (!resp.ok) {
        const text = await resp.text();
        Toast.show('Stress test failed: ' + text, 'error');
        summaryDiv.innerHTML = '<div class="text-xs text-red-400">' + esc(text) + '</div>';
        return;
      }
      const data = await resp.json();
      this._renderStressResults(data);
    } catch (e) {
      Toast.show('Stress test error: ' + e.message, 'error');
      summaryDiv.innerHTML = '<div class="text-xs text-red-400">' + esc(e.message) + '</div>';
    } finally {
      this.stressRunning = false;
      btn.textContent = 'Run Stress Test';
      btn.disabled = false;
      btn.className = 'w-full bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1.5 rounded font-bold';
      progressDiv.textContent = '';
    }
  },

  _renderStressResults(data) {
    const el = document.getElementById('stress-summary');
    if (!el) return;

    // Status code breakdown
    const statusHtml = Object.entries(data.status_codes || {}).sort((a,b) => a[0]-b[0]).map(([code, count]) => {
      const cls = code < 300 ? 'text-green-400' : code < 400 ? 'text-blue-400' : code < 500 ? 'text-yellow-400' : 'text-red-400';
      const pct = (count / data.total_requests * 100).toFixed(1);
      return `<span class="${cls} font-bold">${code}</span>: ${count} (${pct}%)`;
    }).join(' &nbsp; ');

    el.innerHTML = `
      <div class="grid grid-cols-4 gap-3">
        <div class="bg-gray-800 rounded p-3 text-center">
          <div class="text-2xl font-bold text-white">${data.requests_per_sec?.toFixed(0) || 0}</div>
          <div class="text-xs text-gray-400">req/sec</div>
        </div>
        <div class="bg-gray-800 rounded p-3 text-center">
          <div class="text-2xl font-bold text-indigo-400">${data.avg_latency_ms?.toFixed(1) || 0}</div>
          <div class="text-xs text-gray-400">avg ms</div>
        </div>
        <div class="bg-gray-800 rounded p-3 text-center">
          <div class="text-2xl font-bold text-green-400">${((data.total_time_ms || 0) / 1000).toFixed(2)}</div>
          <div class="text-xs text-gray-400">total sec</div>
        </div>
        <div class="bg-gray-800 rounded p-3 text-center">
          <div class="text-2xl font-bold ${data.error_count > 0 ? 'text-red-400' : 'text-green-400'}">${data.error_count || 0}</div>
          <div class="text-xs text-gray-400">errors</div>
        </div>
      </div>
      <div class="bg-gray-800 rounded p-3 mt-2">
        <div class="text-xs text-gray-400 mb-2">Latency Percentiles</div>
        <div class="grid grid-cols-5 gap-2 text-center text-xs">
          <div><div class="text-gray-300 font-bold">${data.min_latency_ms?.toFixed(1) || 0}ms</div><div class="text-gray-500">min</div></div>
          <div><div class="text-gray-300 font-bold">${data.p50_latency_ms?.toFixed(1) || 0}ms</div><div class="text-gray-500">p50</div></div>
          <div><div class="text-yellow-300 font-bold">${data.p90_latency_ms?.toFixed(1) || 0}ms</div><div class="text-gray-500">p90</div></div>
          <div><div class="text-orange-300 font-bold">${data.p95_latency_ms?.toFixed(1) || 0}ms</div><div class="text-gray-500">p95</div></div>
          <div><div class="text-red-300 font-bold">${data.p99_latency_ms?.toFixed(1) || 0}ms</div><div class="text-gray-500">p99</div></div>
        </div>
        <div class="mt-2 text-xs text-gray-500 text-center">max: ${data.max_latency_ms?.toFixed(1) || 0}ms &nbsp;|&nbsp; data: ${formatBytes(data.total_bytes || 0)}</div>
      </div>
      <div class="text-xs text-gray-400 mt-2">Status Codes: ${statusHtml}</div>
    `;
  },

  async op(name) {
    const input = document.getElementById('tools-input').value;
    const output = document.getElementById('tools-output');
    try {
      switch (name) {
        case 'base64enc': output.value = btoa(unescape(encodeURIComponent(input))); break;
        case 'base64dec': output.value = decodeURIComponent(escape(atob(input.trim()))); break;
        case 'urlenc': output.value = encodeURIComponent(input); break;
        case 'urldec': output.value = decodeURIComponent(input); break;
        case 'htmlenc': output.value = input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); break;
        case 'htmldec': { const t = document.createElement('textarea'); t.innerHTML = input; output.value = t.value; break; }
        case 'hexenc': output.value = Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2,'0')).join(''); break;
        case 'hexdec': {
          const hex = input.replace(/\s/g, '');
          const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
          output.value = new TextDecoder().decode(bytes);
          break;
        }
        case 'jwt': {
          const parts = input.trim().split('.');
          if (parts.length < 2) { output.value = 'Invalid JWT'; break; }
          const header = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')))));
          const payload = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))));
          output.value = 'Header:\n' + JSON.stringify(header, null, 2) + '\n\nPayload:\n' + JSON.stringify(payload, null, 2);
          break;
        }
        case 'md5': output.value = await this._md5(input); break;
        case 'sha1': output.value = await this._hash('SHA-1', input); break;
        case 'sha256': output.value = await this._hash('SHA-256', input); break;
      }
    } catch (e) {
      output.value = 'Error: ' + e.message;
    }
  },

  async _hash(algo, str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest(algo, data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  async _md5(str) {
    const k = [], s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    for (let i = 0; i < 64; i++) k[i] = Math.floor(2**32 * Math.abs(Math.sin(i + 1))) >>> 0;

    const bytes = new TextEncoder().encode(str);
    const bits = bytes.length * 8;
    const padded = new Uint8Array(((bytes.length + 8 >> 6) + 1) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, bits & 0xFFFFFFFF, true);
    view.setUint32(padded.length - 4, Math.floor(bits / 2**32), true);

    let a0 = 0x67452301 >>> 0, b0 = 0xefcdab89 >>> 0, c0 = 0x98badcfe >>> 0, d0 = 0x10325476 >>> 0;
    for (let off = 0; off < padded.length; off += 64) {
      const M = [];
      for (let j = 0; j < 16; j++) M[j] = view.getUint32(off + j * 4, true);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i+5) % 16; }
        else { F = C ^ (B | ~D); g = (7*i) % 16; }
        F = (F + A + k[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    return [a0, b0, c0, d0].map(v => {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, v, true);
      return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
    }).join('');
  }
};

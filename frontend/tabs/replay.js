// Replay tab: send/resend HTTP requests (Repeater)
// Features: collections, template chaining, bulk replay, pre-request scripts, fuzzer, sequences, auto-diff
window.ReplayTab = {
  history: [],
  collections: [],
  sequences: [],
  activeCollectionId: null,
  lastResponse: null,
  originalResponse: null,  // For auto-diff (stored when replaying from traffic)
  activeView: 'request',   // 'request', 'fuzz', 'sequence'

  render() {
    return `
      <div class="flex h-[calc(100vh-56px)]">
        <!-- Left: Controls + Request panel -->
        <div class="w-1/2 flex flex-col border-r border-gray-800">
          <!-- Mode tabs -->
          <div class="flex items-center gap-0 bg-gray-900 border-b border-gray-800">
            <button onclick="ReplayTab.switchView('request')" class="px-3 py-2 text-xs ${this.activeView === 'request' ? 'text-white border-b-2 border-indigo-500' : 'text-gray-400 hover:text-white'}">Request</button>
            <button onclick="ReplayTab.switchView('fuzz')" class="px-3 py-2 text-xs ${this.activeView === 'fuzz' ? 'text-white border-b-2 border-indigo-500' : 'text-gray-400 hover:text-white'}">Fuzzer</button>
            <button onclick="ReplayTab.switchView('sequence')" class="px-3 py-2 text-xs ${this.activeView === 'sequence' ? 'text-white border-b-2 border-indigo-500' : 'text-gray-400 hover:text-white'}">Sequences</button>
            <div class="ml-auto flex items-center gap-1 pr-2">
              <select id="replay-collection" onchange="ReplayTab.selectCollection(this.value)"
                class="bg-gray-800 text-gray-300 text-xs px-1 py-1 rounded border border-gray-700 w-24">
                <option value="">Collection</option>
              </select>
              <button onclick="ReplayTab.newCollection()" class="text-xs text-indigo-400 hover:text-indigo-300 px-1">+</button>
              <button onclick="ReplayTab.saveToCollection()" class="text-xs text-green-400 hover:text-green-300 px-1">Save</button>
            </div>
          </div>

          <div id="replay-left-panel" class="flex-1 overflow-y-auto">
            ${this._renderLeftPanel()}
          </div>
        </div>

        <!-- Response panel -->
        <div class="w-1/2 p-4 overflow-y-auto">
          <h3 class="text-sm font-bold text-gray-400 mb-2">Response</h3>
          <div id="replay-response" class="text-gray-600 text-xs">Send a request to see the response</div>
        </div>
      </div>`;
  },

  switchView(view) {
    this.activeView = view;
    const panel = document.getElementById('replay-left-panel');
    if (panel) panel.innerHTML = this._renderLeftPanel();
  },

  _renderLeftPanel() {
    switch (this.activeView) {
      case 'fuzz': return this._renderFuzzPanel();
      case 'sequence': return this._renderSequencePanel();
      default: return this._renderRequestPanel();
    }
  },

  _renderRequestPanel() {
    return `
      <div class="p-4 space-y-3">
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
          <textarea id="replay-headers" rows="5" placeholder="Content-Type: application/json"
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </div>
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Body</h3>
          <textarea id="replay-body" rows="6" placeholder='{"key": "value"}'
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </div>
        <details class="text-xs">
          <summary class="text-gray-400 cursor-pointer hover:text-gray-300">Pre-request Script</summary>
          <textarea id="replay-prescript" rows="3" placeholder="// JS: modify method, url, headers, body before send"
            class="w-full mt-1 bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </details>
        <details class="text-xs">
          <summary class="text-gray-400 cursor-pointer hover:text-gray-300">Template Variables</summary>
          <div class="mt-1 text-gray-500 space-y-0.5">
            <div><code class="text-indigo-400">{{prev.json.field}}</code> — Previous JSON field</div>
            <div><code class="text-indigo-400">{{prev.header.name}}</code> — Previous header</div>
            <div><code class="text-indigo-400">{{timestamp}}</code> / <code class="text-indigo-400">{{uuid}}</code></div>
          </div>
        </details>
        <div class="flex gap-2">
          <button onclick="ReplayTab.send()" id="replay-send-btn" class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-6 py-2 rounded">Send</button>
          <button onclick="ReplayTab.bulkReplay()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-4 py-2 rounded" title="Replay all in collection">Bulk</button>
          <button onclick="ReplayTab.clear()" class="bg-gray-700 hover:bg-gray-600 text-white text-xs px-4 py-2 rounded">Clear</button>
        </div>
        <div class="mt-3">
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">History</h3>
          <div id="replay-history" class="space-y-1 max-h-40 overflow-y-auto"></div>
        </div>
      </div>`;
  },

  // ── Fuzzer Panel ─────────────────────────────────────────

  _renderFuzzPanel() {
    return `
      <div class="p-4 space-y-3">
        <h2 class="text-sm font-bold text-white">Fuzzer</h2>
        <div class="flex gap-2">
          <select id="fuzz-method" class="bg-gray-800 text-gray-300 text-xs px-2 py-2 rounded border border-gray-700">
            <option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
          </select>
          <input id="fuzz-url" type="text" placeholder="https://example.com/api/users/{{fuzz.id}}"
            class="flex-1 bg-gray-800 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Headers</h3>
          <textarea id="fuzz-headers" rows="3" placeholder="Authorization: Bearer {{fuzz.token}}"
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </div>
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Body</h3>
          <textarea id="fuzz-body" rows="4" placeholder='{"id": {{fuzz.id}}, "name": "{{fuzz.name}}"}'
            class="w-full bg-gray-900 text-gray-300 text-xs p-2 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </div>
        <div class="bg-gray-900 rounded p-3 space-y-2">
          <h3 class="text-xs font-bold text-gray-400 uppercase">Variables</h3>
          <div id="fuzz-variables" class="space-y-1">
            <div class="flex gap-2 items-center text-xs">
              <input type="text" placeholder="name" class="fuzz-var-name bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700 w-20">
              <select class="fuzz-var-type bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700" onchange="ReplayTab._updateFuzzArgs(this)">
                <option value="range">Range</option>
                <option value="wordlist">Wordlist</option>
                <option value="random">Random</option>
                <option value="uuid">UUID</option>
              </select>
              <input type="text" placeholder="1,100" class="fuzz-var-args flex-1 bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700">
              <button onclick="this.parentElement.remove()" class="text-red-400 hover:text-red-300">x</button>
            </div>
          </div>
          <button onclick="ReplayTab.addFuzzVariable()" class="text-xs text-indigo-400 hover:text-indigo-300">+ Add Variable</button>
        </div>
        <div class="flex items-center gap-3">
          <label class="text-xs text-gray-400">Iterations:</label>
          <input type="number" id="fuzz-iterations" value="10" min="1" max="1000"
            class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 w-20">
          <label class="text-xs text-gray-400">Delay (ms):</label>
          <input type="number" id="fuzz-delay" value="0" min="0"
            class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 w-20">
        </div>
        <button onclick="ReplayTab.startFuzz()" id="fuzz-start-btn" class="bg-red-600 hover:bg-red-500 text-white text-sm px-6 py-2 rounded">Start Fuzz</button>
        <div class="text-xs text-gray-500">
          Use <code class="text-indigo-400">{{fuzz.varname}}</code> in URL/headers/body. <code class="text-indigo-400">{{fuzz.i}}</code> = iteration index.
        </div>
      </div>`;
  },

  _updateFuzzArgs(select) {
    const argsInput = select.parentElement.querySelector('.fuzz-var-args');
    switch (select.value) {
      case 'range': argsInput.placeholder = '1,100'; break;
      case 'wordlist': argsInput.placeholder = 'admin,user,test'; break;
      case 'random': argsInput.placeholder = '8 (length)'; break;
      case 'uuid': argsInput.placeholder = '(no args needed)'; break;
    }
  },

  addFuzzVariable() {
    const container = document.getElementById('fuzz-variables');
    const div = document.createElement('div');
    div.className = 'flex gap-2 items-center text-xs';
    div.innerHTML = `
      <input type="text" placeholder="name" class="fuzz-var-name bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700 w-20">
      <select class="fuzz-var-type bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700" onchange="ReplayTab._updateFuzzArgs(this)">
        <option value="range">Range</option>
        <option value="wordlist">Wordlist</option>
        <option value="random">Random</option>
        <option value="uuid">UUID</option>
      </select>
      <input type="text" placeholder="1,100" class="fuzz-var-args flex-1 bg-gray-800 text-gray-300 px-2 py-1 rounded border border-gray-700">
      <button onclick="this.parentElement.remove()" class="text-red-400 hover:text-red-300">x</button>`;
    container.appendChild(div);
  },

  async startFuzz() {
    const method = document.getElementById('fuzz-method').value;
    const url = document.getElementById('fuzz-url').value;
    if (!url) { Toast.show('URL is required', 'warn'); return; }
    const headersText = document.getElementById('fuzz-headers').value;
    const body = document.getElementById('fuzz-body').value;
    const iterations = parseInt(document.getElementById('fuzz-iterations').value) || 10;
    const delay_ms = parseInt(document.getElementById('fuzz-delay').value) || 0;

    const headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });

    const variables = {};
    document.querySelectorAll('#fuzz-variables > div').forEach(row => {
      const name = row.querySelector('.fuzz-var-name')?.value;
      const type = row.querySelector('.fuzz-var-type')?.value;
      const args = row.querySelector('.fuzz-var-args')?.value || '';
      if (name) variables[name] = type + ':' + args;
    });

    const btn = document.getElementById('fuzz-start-btn');
    btn.textContent = 'Fuzzing...';
    btn.disabled = true;

    try {
      const resp = await authFetch('/api/replay/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, url, headers, body, iterations, variables, delay_ms })
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        Toast.show(err.detail || 'Fuzz failed', 'error');
        return;
      }
      const data = await resp.json();
      this._renderFuzzResults(data.results);
    } catch (e) {
      Toast.show('Fuzz error: ' + e.message, 'error');
    } finally {
      btn.textContent = 'Start Fuzz';
      btn.disabled = false;
    }
  },

  _renderFuzzResults(results) {
    // Group by status code for summary
    const statusGroups = {};
    results.forEach(r => {
      const key = r.status_code || 'ERR';
      statusGroups[key] = (statusGroups[key] || 0) + 1;
    });
    const summary = Object.entries(statusGroups)
      .map(([s, c]) => `<span class="${parseInt(s) < 300 ? 'text-green-400' : parseInt(s) < 500 ? 'text-yellow-400' : 'text-red-400'}">${s}: ${c}</span>`)
      .join(' | ');

    document.getElementById('replay-response').innerHTML = `
      <div class="space-y-2">
        <div class="flex items-center gap-3">
          <h4 class="text-sm font-bold text-white">Fuzz Results (${results.length})</h4>
          <span class="text-xs">${summary}</span>
        </div>
        <div class="max-h-96 overflow-y-auto">
          <table class="w-full text-xs">
            <thead class="text-gray-400 border-b border-gray-700">
              <tr><th class="text-left py-1 w-8">#</th><th class="text-left w-16">Status</th><th class="text-left w-16">Time</th><th class="text-left w-16">Size</th><th class="text-left">Error</th></tr>
            </thead>
            <tbody>
              ${results.map(r => {
                const cls = r.status_code < 300 ? 'text-green-400' : r.status_code < 500 ? 'text-yellow-400' : 'text-red-400';
                return `<tr class="border-b border-gray-800/50 hover:bg-gray-900 cursor-pointer" onclick="TrafficTab.selectFlow && _switchTab('traffic')">
                  <td class="py-1 text-gray-500">${r.iteration}</td>
                  <td class="${cls} font-bold">${r.status_code || 'ERR'}</td>
                  <td class="text-gray-400">${r.duration_ms}ms</td>
                  <td class="text-gray-400">${formatBytes(r.size)}</td>
                  <td class="text-red-400">${r.error ? esc(r.error) : ''}</td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  },

  // ── Sequence Panel ───────────────────────────────────────

  _renderSequencePanel() {
    return `
      <div class="p-4 space-y-3">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-bold text-white">Sequences</h2>
          <div class="flex gap-2">
            <button onclick="ReplayTab.newSequence()" class="text-xs text-indigo-400 hover:text-indigo-300 px-2 py-1">New</button>
            <button onclick="ReplayTab.startRecording()" id="seq-record-btn" class="text-xs text-red-400 hover:text-red-300 px-2 py-1">Record</button>
          </div>
        </div>
        <div id="seq-list" class="space-y-1"></div>
        <div id="seq-editor" class="hidden space-y-3">
          <div class="flex items-center gap-2">
            <input type="text" id="seq-name" placeholder="Sequence name"
              class="flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 focus:outline-none focus:border-indigo-500">
            <button onclick="ReplayTab.saveSequence()" class="text-xs bg-green-700 hover:bg-green-600 text-white px-3 py-1 rounded">Save</button>
          </div>
          <div id="seq-steps" class="space-y-2"></div>
          <button onclick="ReplayTab.addSequenceStep()" class="text-xs text-indigo-400 hover:text-indigo-300">+ Add Step</button>
          <div class="flex gap-2">
            <button onclick="ReplayTab.runSequence()" id="seq-run-btn" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-4 py-2 rounded">Run Sequence</button>
          </div>
        </div>
      </div>`;
  },

  _editingSequence: null,
  _recording: false,
  _recordedSteps: [],

  startRecording() {
    if (this._recording) {
      this._recording = false;
      document.getElementById('seq-record-btn').textContent = 'Record';
      Toast.show(`Recorded ${this._recordedSteps.length} steps`, 'success');
      this._showSequenceEditor(this._recordedSteps);
      return;
    }
    this._recording = true;
    this._recordedSteps = [];
    document.getElementById('seq-record-btn').textContent = 'Stop Recording';
    Toast.show('Recording... send requests via Replay to capture steps', 'info');
  },

  _captureStep(method, url, headers, body, response) {
    if (!this._recording) return;
    this._recordedSteps.push({
      name: `Step ${this._recordedSteps.length + 1}: ${method} ${url.split('?')[0].split('/').pop() || '/'}`,
      method, url, headers, body,
      pre_script: '',
      extract: {},
    });
  },

  _showSequenceEditor(steps) {
    const editor = document.getElementById('seq-editor');
    if (!editor) return;
    editor.classList.remove('hidden');
    this._editingSequence = { steps: steps || [] };
    this._renderSequenceSteps();
  },

  _renderSequenceSteps() {
    const container = document.getElementById('seq-steps');
    if (!container || !this._editingSequence) return;
    container.innerHTML = this._editingSequence.steps.map((step, i) => `
      <div class="bg-gray-900 rounded p-2 space-y-1 border border-gray-700">
        <div class="flex items-center gap-2 text-xs">
          <span class="text-gray-500 w-6">${i + 1}.</span>
          <input type="text" value="${esc(step.name)}" onchange="ReplayTab._editingSequence.steps[${i}].name=this.value"
            class="flex-1 bg-transparent text-gray-300 focus:outline-none focus:bg-gray-800 px-1 rounded">
          <span class="text-indigo-400">${step.method}</span>
          <button onclick="ReplayTab._removeStep(${i})" class="text-red-400 hover:text-red-300">x</button>
        </div>
        <div class="text-xs text-gray-500 truncate pl-8">${esc(step.url)}</div>
        <details class="pl-8">
          <summary class="text-xs text-gray-500 cursor-pointer">Extract Variables</summary>
          <div class="mt-1 space-y-1">
            <div class="flex gap-1 text-xs" id="seq-extract-${i}">
              ${Object.entries(step.extract || {}).map(([k, v]) =>
                `<input type="text" value="${esc(k)}" placeholder="var name" class="bg-gray-800 text-gray-300 px-1 py-0.5 rounded w-20 border border-gray-700">
                 <input type="text" value="${esc(v)}" placeholder="json:path or header:name" class="bg-gray-800 text-gray-300 px-1 py-0.5 rounded flex-1 border border-gray-700">`
              ).join('')}
            </div>
            <button onclick="ReplayTab._addExtract(${i})" class="text-xs text-indigo-400">+ extract</button>
            <div class="text-xs text-gray-600 mt-1">Syntax: <code>json:data.token</code>, <code>header:Set-Cookie</code>, <code>regex:token=(.+?)&</code></div>
          </div>
        </details>
      </div>
    `).join('');
  },

  _removeStep(i) {
    this._editingSequence.steps.splice(i, 1);
    this._renderSequenceSteps();
  },

  _addExtract(stepIdx) {
    const step = this._editingSequence.steps[stepIdx];
    const name = prompt('Variable name:');
    if (!name) return;
    const spec = prompt('Extract spec (e.g., json:data.token):', 'json:');
    if (!spec) return;
    step.extract[name] = spec;
    this._renderSequenceSteps();
  },

  addSequenceStep() {
    if (!this._editingSequence) this._editingSequence = { steps: [] };
    const method = document.getElementById('replay-method')?.value || 'GET';
    const url = document.getElementById('replay-url')?.value || '';
    this._editingSequence.steps.push({
      name: `Step ${this._editingSequence.steps.length + 1}`,
      method, url, headers: {}, body: '', pre_script: '', extract: {},
    });
    this._renderSequenceSteps();
  },

  newSequence() {
    this._editingSequence = { steps: [] };
    this._showSequenceEditor([]);
    document.getElementById('seq-name').value = '';
  },

  async saveSequence() {
    const name = document.getElementById('seq-name')?.value || 'Untitled';
    if (!this._editingSequence || !this._editingSequence.steps.length) {
      Toast.show('Add steps first', 'warn');
      return;
    }
    try {
      const resp = await authFetch('/api/replay/sequences', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, steps: this._editingSequence.steps })
      });
      if (!resp.ok) { Toast.show('Failed to save', 'error'); return; }
      Toast.show('Sequence saved', 'success');
      this.loadSequences();
    } catch { Toast.show('Failed to save', 'error'); }
  },

  async loadSequences() {
    try {
      const resp = await authFetch('/api/replay/sequences');
      if (!resp.ok) return;
      this.sequences = await resp.json();
      this._renderSequenceList();
    } catch {}
  },

  _renderSequenceList() {
    const el = document.getElementById('seq-list');
    if (!el) return;
    el.innerHTML = this.sequences.length === 0
      ? '<div class="text-gray-600 text-xs">No saved sequences</div>'
      : this.sequences.map(s => `
        <div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1.5 text-xs">
          <span class="text-gray-300 flex-1">${esc(s.name)}</span>
          <span class="text-gray-500">${s.steps.length} steps</span>
          <button onclick="ReplayTab.playSequence('${s.id}')" class="text-green-400 hover:text-green-300 px-1">Play</button>
          <button onclick="ReplayTab.editSequence('${s.id}')" class="text-indigo-400 hover:text-indigo-300 px-1">Edit</button>
          <button onclick="ReplayTab.deleteSequence('${s.id}')" class="text-red-400 hover:text-red-300 px-1">x</button>
        </div>
      `).join('');
  },

  editSequence(id) {
    const seq = this.sequences.find(s => s.id === id);
    if (!seq) return;
    document.getElementById('seq-name').value = seq.name;
    this._showSequenceEditor(seq.steps);
  },

  async deleteSequence(id) {
    if (!confirm('Delete this sequence?')) return;
    try {
      await authFetch(`/api/replay/sequences/${id}`, { method: 'DELETE' });
      this.sequences = this.sequences.filter(s => s.id !== id);
      this._renderSequenceList();
      Toast.show('Deleted', 'success');
    } catch {}
  },

  async playSequence(id) {
    const seq = this.sequences.find(s => s.id === id);
    if (!seq) return;
    await this.runSequence(seq.steps);
  },

  async runSequence(stepsOverride) {
    const steps = stepsOverride || (this._editingSequence ? this._editingSequence.steps : []);
    if (!steps.length) { Toast.show('No steps', 'warn'); return; }

    const btn = document.getElementById('seq-run-btn');
    if (btn) { btn.textContent = 'Running...'; btn.disabled = true; }

    try {
      const resp = await authFetch('/api/replay/sequence', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ steps })
      });
      if (!resp.ok) { Toast.show('Sequence failed', 'error'); return; }
      const data = await resp.json();

      document.getElementById('replay-response').innerHTML = `
        <div class="space-y-2">
          <h4 class="text-sm font-bold text-white">Sequence Results</h4>
          ${data.results.map(r => {
            const cls = (r.status_code || 0) < 300 ? 'text-green-400' : (r.status_code || 0) < 500 ? 'text-yellow-400' : 'text-red-400';
            const extracted = r.extracted ? Object.entries(r.extracted).map(([k,v]) =>
              `<span class="text-indigo-400">${esc(k)}</span>=<span class="text-green-400">"${esc(String(v).substring(0,50))}"</span>`
            ).join(', ') : '';
            return `<div class="bg-gray-900 rounded px-3 py-2 text-xs">
              <div class="flex items-center gap-2">
                <span class="text-gray-500">Step ${r.step + 1}</span>
                <span class="${cls} font-bold">${r.status_code || 'ERR'}</span>
                <span class="text-gray-300">${esc(r.name)}</span>
                <span class="ml-auto text-gray-500">${r.duration_ms || 0}ms</span>
              </div>
              ${extracted ? `<div class="mt-1 text-xs">Extracted: ${extracted}</div>` : ''}
              ${r.error ? `<div class="text-red-400 mt-1">${esc(r.error)}</div>` : ''}
            </div>`;
          }).join('')}
          ${Object.keys(data.variables || {}).length ? `
          <div class="bg-gray-800 rounded p-2 text-xs">
            <h5 class="text-gray-400 font-bold mb-1">Final Variables</h5>
            ${Object.entries(data.variables).map(([k,v]) =>
              `<div><span class="text-indigo-400">${esc(k)}</span>: <span class="text-green-400">${esc(String(v).substring(0,100))}</span></div>`
            ).join('')}
          </div>` : ''}
        </div>`;
      Toast.show(`Sequence done: ${data.results.length} steps`, 'success');
    } catch (e) {
      Toast.show('Sequence error: ' + e.message, 'error');
    } finally {
      if (btn) { btn.textContent = 'Run Sequence'; btn.disabled = false; }
    }
  },

  // ── Core send / load / collections ─────────────────────

  load() {
    if (window._replayPrefill) {
      const p = window._replayPrefill;
      // Store original response for auto-diff
      if (p._originalResponse) {
        this.originalResponse = p._originalResponse;
      }
      setTimeout(() => {
        const methodEl = document.getElementById('replay-method');
        const urlEl = document.getElementById('replay-url');
        const headersEl = document.getElementById('replay-headers');
        const bodyEl = document.getElementById('replay-body');
        if (methodEl) methodEl.value = p.method || 'GET';
        if (urlEl) urlEl.value = p.url || '';
        if (headersEl) headersEl.value = Object.entries(p.headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');
        if (bodyEl) bodyEl.value = p.body || '';
      }, 0);
      window._replayPrefill = null;
    }
    this.renderHistory();
    this.loadCollections();
    this.loadSequences();
  },

  _substituteTemplates(text) {
    if (!text || !text.includes('{{')) return text;
    const prev = this.lastResponse;
    return text.replace(/\{\{([^}]+)\}\}/g, (match, key) => {
      key = key.trim();
      if (key === 'timestamp') return String(Date.now());
      if (key === 'uuid') return crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random()*16|0; return (c==='x'?r:(r&0x3|0x8)).toString(16); });
      if (!prev) return match;
      if (key === 'prev.status') return String(prev.status_code || '');
      if (key === 'prev.body') return prev.body || '';
      if (key.startsWith('prev.json.')) {
        const path = key.substring(10);
        try {
          const obj = JSON.parse(prev.body || '{}');
          return String(path.split('.').reduce((o, k) => o && o[k], obj) || '');
        } catch { return ''; }
      }
      if (key.startsWith('prev.header.')) {
        const hdr = key.substring(12).toLowerCase();
        if (prev.headers) {
          for (const [k, v] of Object.entries(prev.headers)) {
            if (k.toLowerCase() === hdr) return v;
          }
        }
        return '';
      }
      return match;
    });
  },

  _runPreScript(script, method, url, headers, body) {
    if (!script || !script.trim()) return { method, url, headers, body };
    try {
      const fn = new Function('method', 'url', 'headers', 'body', script + '\nreturn {method, url, headers, body};');
      return fn(method, url, headers, body);
    } catch (e) {
      Toast.show('Pre-script error: ' + e.message, 'error');
      return { method, url, headers, body };
    }
  },

  async send() {
    let method = document.getElementById('replay-method').value;
    let url = this._substituteTemplates(document.getElementById('replay-url').value);
    if (!url) { Toast.show('URL is required', 'warn'); return; }

    const headersText = this._substituteTemplates(document.getElementById('replay-headers').value);
    let body = this._substituteTemplates(document.getElementById('replay-body').value);
    let headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });

    const preScript = document.getElementById('replay-prescript')?.value || '';
    const scripted = this._runPreScript(preScript, method, url, headers, body);
    method = scripted.method; url = scripted.url; headers = scripted.headers; body = scripted.body;

    const btn = document.getElementById('replay-send-btn');
    btn.textContent = 'Sending...';
    btn.disabled = true;

    try {
      const resp = await authFetch('/api/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, url, headers, body })
      });

      if (!resp.ok) {
        let errMsg = 'Request failed';
        try { const errData = await resp.json(); errMsg = errData.detail || errMsg; } catch { errMsg = await resp.text() || errMsg; }
        document.getElementById('replay-response').innerHTML = `<div class="text-red-400">${esc(errMsg)}</div>`;
        return;
      }

      const data = await resp.json();
      this.lastResponse = data;

      // Capture for sequence recording
      this._captureStep(method, url, headers, body, data);

      this.history.unshift({ method, url, status: data.status_code, duration: data.duration_ms, headers: { ...headers }, body });
      if (this.history.length > 50) this.history.pop();
      this.renderHistory();

      // Render response with auto-diff if original exists
      this._renderResponse(data);
    } catch (e) {
      document.getElementById('replay-response').innerHTML = `<div class="text-red-400">Error: ${esc(e.message)}</div>`;
    } finally {
      btn.textContent = 'Send';
      btn.disabled = false;
    }
  },

  _renderResponse(data) {
    const statusCls = data.status_code < 300 ? 'text-green-400' : data.status_code < 400 ? 'text-blue-400' : data.status_code < 500 ? 'text-yellow-400' : 'text-red-400';
    const ct = (data.headers || {})['content-type'] || '';
    let bodyHtml;
    if (ct.includes('json')) {
      try { bodyHtml = highlightJSON(JSON.stringify(JSON.parse(data.body || ''), null, 2)); }
      catch { bodyHtml = esc(data.body || ''); }
    } else {
      bodyHtml = esc(data.body || '');
    }

    const respHeaders = Object.entries(data.headers || {}).map(([k,v]) =>
      `<span class="text-green-400">${esc(k)}</span>: <span class="text-gray-300">${esc(v)}</span>`
    ).join('<br>');

    // Auto-diff section
    let diffSection = '';
    if (this.originalResponse) {
      const orig = this.originalResponse;
      const statusChanged = orig.status_code !== data.status_code;
      const durationDelta = data.duration_ms - (orig.duration_ms || 0);

      // Diff bodies
      let origBody = orig.response_body || orig.body || '';
      let newBody = data.body || '';
      try { origBody = JSON.stringify(JSON.parse(origBody), null, 2); } catch {}
      try { newBody = JSON.stringify(JSON.parse(newBody), null, 2); } catch {}

      const bodyDiffResult = lineDiff(origBody, newBody);
      const hasChanges = bodyDiffResult.left.some(l => l.type !== 'same');

      diffSection = `
        <div class="mt-3 border-t border-gray-700 pt-3">
          <h4 class="text-xs font-bold text-yellow-400 uppercase mb-2">Auto-Diff vs Original</h4>
          <div class="flex gap-3 text-xs mb-2">
            <span>Status: <span class="${statusChanged ? 'text-yellow-400' : 'text-gray-400'}">${esc(orig.status_code || '?')} → ${esc(data.status_code)}</span></span>
            <span>Duration: <span class="${Math.abs(durationDelta) > 100 ? 'text-yellow-400' : 'text-gray-400'}">${durationDelta > 0 ? '+' : ''}${durationDelta.toFixed(0)}ms</span></span>
          </div>
          ${hasChanges ? `
          <div class="flex gap-0 text-xs">
            <div class="flex-1">
              <div class="text-gray-500 mb-1">Original</div>
              <pre class="body-preview bg-gray-900 rounded-l p-2" style="max-height:200px">${bodyDiffResult.left.map(l =>
                l.type === 'removed' ? `<span class="diff-removed">${esc(l.text)}</span>` :
                l.type === 'empty' ? '' : esc(l.text)
              ).join('\n')}</pre>
            </div>
            <div class="flex-1">
              <div class="text-gray-500 mb-1">New</div>
              <pre class="body-preview bg-gray-900 rounded-r p-2" style="max-height:200px">${bodyDiffResult.right.map(l =>
                l.type === 'added' ? `<span class="diff-added">${esc(l.text)}</span>` :
                l.type === 'empty' ? '' : esc(l.text)
              ).join('\n')}</pre>
            </div>
          </div>` : '<div class="text-green-400 text-xs">No body changes detected</div>'}
        </div>`;
    }

    document.getElementById('replay-response').innerHTML = `
      <div class="space-y-3">
        <div class="flex items-center gap-3">
          <span class="${statusCls} font-bold">${esc(data.status_code)} ${esc(data.reason || '')}</span>
          <span class="text-gray-500 text-xs">${esc(data.duration_ms)}ms</span>
          ${this.originalResponse ? '<span class="badge bg-yellow-900 text-yellow-300">DIFF</span>' : ''}
        </div>
        <div>
          <h4 class="text-xs font-bold text-gray-400 uppercase mb-1">Headers</h4>
          <div class="bg-gray-900 rounded p-2 text-xs">${respHeaders}</div>
        </div>
        <div>
          <h4 class="text-xs font-bold text-gray-400 uppercase mb-1">Body</h4>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${bodyHtml}</pre>
        </div>
        ${diffSection}
      </div>`;
  },

  // ── Bulk replay (from collections) ──────────────────────

  async bulkReplay() {
    if (!this.activeCollectionId) { Toast.show('Select a collection first', 'warn'); return; }
    const col = this.collections.find(c => c.id === this.activeCollectionId);
    if (!col || !col.requests.length) { Toast.show('Collection has no requests', 'warn'); return; }

    const results = [];
    for (const req of col.requests) {
      const url = this._substituteTemplates(req.url);
      const body = this._substituteTemplates(req.body || '');
      let headers = {};
      for (const [k, v] of Object.entries(req.headers || {})) {
        headers[k] = this._substituteTemplates(v);
      }
      if (req.pre_script) {
        const scripted = this._runPreScript(req.pre_script, req.method, url, headers, body);
        Object.assign(headers, scripted.headers);
      }
      try {
        const resp = await authFetch('/api/replay', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ method: req.method, url, headers, body })
        });
        if (resp.ok) {
          const data = await resp.json();
          this.lastResponse = data;
          results.push({ name: req.name, status: data.status_code, duration: data.duration_ms });
        } else {
          results.push({ name: req.name, status: 'ERR', duration: 0 });
        }
      } catch {
        results.push({ name: req.name, status: 'ERR', duration: 0 });
      }
    }

    document.getElementById('replay-response').innerHTML = `
      <div class="space-y-2">
        <h4 class="text-sm font-bold text-white">Bulk Results (${results.length})</h4>
        ${results.map(r => {
          const cls = r.status < 300 ? 'text-green-400' : r.status < 500 ? 'text-yellow-400' : 'text-red-400';
          return `<div class="flex items-center gap-2 text-xs bg-gray-900 rounded px-2 py-1">
            <span class="${cls} font-bold w-10">${r.status}</span>
            <span class="text-gray-300">${esc(r.name)}</span>
            <span class="ml-auto text-gray-600">${r.duration}ms</span>
          </div>`;
        }).join('')}
      </div>`;
    Toast.show(`Bulk done: ${results.length} requests`, 'success');
  },

  // ── Collections ─────────────────────────────────────────

  async loadCollections() {
    try {
      const resp = await authFetch('/api/collections');
      if (!resp.ok) return;
      this.collections = await resp.json();
      this._renderCollectionSelect();
    } catch {}
  },

  _renderCollectionSelect() {
    const select = document.getElementById('replay-collection');
    if (!select) return;
    select.innerHTML = '<option value="">Collection</option>' +
      this.collections.map(c => `<option value="${c.id}" ${c.id === this.activeCollectionId ? 'selected' : ''}>${esc(c.name)} (${c.requests.length})</option>`).join('');
  },

  selectCollection(id) {
    this.activeCollectionId = id || null;
    if (id) {
      const col = this.collections.find(c => c.id === id);
      if (col && col.requests.length) this._renderCollectionRequests(col);
    }
  },

  _renderCollectionRequests(col) {
    const el = document.getElementById('replay-history');
    if (!el) return;
    el.innerHTML = `<div class="text-xs text-indigo-400 mb-1">${esc(col.name)}</div>` +
      col.requests.map((r, i) => `
        <div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1 text-xs cursor-pointer hover:bg-gray-800"
             onclick="ReplayTab.loadCollectionRequest(${i})">
          <span class="text-gray-500 w-10">${r.method}</span>
          <span class="text-gray-400 truncate">${esc(r.name || r.url)}</span>
        </div>`).join('');
  },

  loadCollectionRequest(idx) {
    const col = this.collections.find(c => c.id === this.activeCollectionId);
    if (!col || !col.requests[idx]) return;
    const r = col.requests[idx];
    if (this.activeView !== 'request') this.switchView('request');
    setTimeout(() => {
      document.getElementById('replay-method').value = r.method || 'GET';
      document.getElementById('replay-url').value = r.url || '';
      document.getElementById('replay-headers').value = Object.entries(r.headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');
      document.getElementById('replay-body').value = r.body || '';
      const ps = document.getElementById('replay-prescript');
      if (ps) ps.value = r.pre_script || '';
    }, 0);
  },

  async newCollection() {
    const name = prompt('Collection name:');
    if (!name) return;
    try {
      const resp = await authFetch('/api/collections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, requests: [] })
      });
      if (!resp.ok) { Toast.show('Failed', 'error'); return; }
      const col = await resp.json();
      this.collections.push(col);
      this.activeCollectionId = col.id;
      this._renderCollectionSelect();
      Toast.show('Created', 'success');
    } catch { Toast.show('Failed', 'error'); }
  },

  async saveToCollection() {
    if (!this.activeCollectionId) { Toast.show('Select a collection', 'warn'); return; }
    const method = document.getElementById('replay-method')?.value || 'GET';
    const url = document.getElementById('replay-url')?.value;
    if (!url) { Toast.show('URL required', 'warn'); return; }
    const headersText = document.getElementById('replay-headers')?.value || '';
    const body = document.getElementById('replay-body')?.value || '';
    const preScript = document.getElementById('replay-prescript')?.value || '';
    const headers = {};
    headersText.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    let defaultName = method + ' ' + url;
    try { defaultName = method + ' ' + new URL(url).pathname; } catch {}
    const name = prompt('Request name:', defaultName);
    if (!name) return;
    const col = this.collections.find(c => c.id === this.activeCollectionId);
    if (!col) return;
    col.requests.push({ name, method, url, headers, body, pre_script: preScript });
    try {
      await authFetch(`/api/collections/${col.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: col.name, requests: col.requests })
      });
      Toast.show('Saved', 'success');
      this._renderCollectionSelect();
    } catch { Toast.show('Failed', 'error'); }
  },

  clear() {
    ['replay-method', 'replay-url', 'replay-headers', 'replay-body', 'replay-prescript'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.tagName === 'SELECT' ? el.value = 'GET' : el.value = '';
    });
    this.originalResponse = null;
    document.getElementById('replay-response').innerHTML = '<span class="text-gray-600">Send a request to see the response</span>';
  },

  renderHistory() {
    const el = document.getElementById('replay-history');
    if (!el) return;
    if (this.activeCollectionId) {
      const col = this.collections.find(c => c.id === this.activeCollectionId);
      if (col) { this._renderCollectionRequests(col); return; }
    }
    el.innerHTML = this.history.length === 0
      ? '<div class="text-gray-600 text-xs">No history yet</div>'
      : this.history.map((h, i) => `
        <div class="flex items-center gap-2 bg-gray-900 rounded px-2 py-1 text-xs cursor-pointer hover:bg-gray-800"
             onclick="ReplayTab.loadFromHistory(${i})">
          <span class="text-gray-500 w-10">${h.method}</span>
          <span class="${h.status < 300 ? 'text-green-400' : h.status < 500 ? 'text-yellow-400' : 'text-red-400'}">${h.status}</span>
          <span class="text-gray-400 truncate">${esc(h.url)}</span>
          <span class="ml-auto text-gray-600">${h.duration}ms</span>
        </div>`).join('');
  },

  loadFromHistory(i) {
    const h = this.history[i];
    if (!h) return;
    if (this.activeView !== 'request') this.switchView('request');
    setTimeout(() => {
      document.getElementById('replay-method').value = h.method;
      document.getElementById('replay-url').value = h.url;
      document.getElementById('replay-headers').value = Object.entries(h.headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n');
      document.getElementById('replay-body').value = h.body || '';
    }, 0);
  }
};

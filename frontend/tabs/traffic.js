// Traffic tab: split pane with flow list + detail, search, export/import, context menu
window.TrafficTab = {
  flows: [],
  flowMap: {},
  selectedId: null,
  autoScroll: true,
  searchMode: false,
  highlightRules: [],

  render() {
    return `
      <div class="split-pane">
        <div class="flow-list w-1/2 min-w-[300px]" id="flow-list">
          <div class="flex items-center justify-between px-3 py-2 bg-gray-900 border-b border-gray-800 sticky top-0 z-10">
            <div class="flex items-center gap-2">
              <input type="text" id="flow-filter" placeholder="Filter..."
                class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 w-36 focus:outline-none focus:border-indigo-500"
                oninput="TrafficTab.applyFilter()">
              <button onclick="TrafficTab.toggleSearch()" id="search-btn" class="text-xs text-gray-400 hover:text-white px-2 py-1 rounded hover:bg-gray-800">Search</button>
            </div>
            <div class="flex items-center gap-2">
              <label class="text-xs text-gray-500 flex items-center gap-1">
                <input type="checkbox" checked onchange="TrafficTab.autoScroll=this.checked" class="accent-indigo-500"> Auto
              </label>
              <div class="relative">
                <button onclick="TrafficTab.toggleExportMenu()" class="text-xs text-gray-400 hover:text-white px-2 py-1 rounded hover:bg-gray-800">Export</button>
              </div>
              <label class="text-xs text-indigo-400 hover:text-indigo-300 cursor-pointer px-2 py-1 rounded hover:bg-gray-800">
                Import <input type="file" accept=".har,.json" class="hidden" onchange="TrafficTab.importHAR(this)">
              </label>
              <button onclick="TrafficTab.clearFlows()" class="text-xs text-red-400 hover:text-red-300 px-2 py-1 rounded hover:bg-gray-800">Clear</button>
            </div>
          </div>
          <div id="search-bar" class="hidden px-3 py-2 bg-gray-900 border-b border-gray-800 flex items-center gap-2">
            <input type="text" id="search-input" placeholder="Search bodies, headers (regex supported)..."
              class="flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 focus:outline-none focus:border-indigo-500"
              onkeydown="if(event.key==='Enter')TrafficTab.doSearch()">
            <label class="text-xs text-gray-500 flex items-center gap-1">
              <input type="checkbox" id="search-regex" class="accent-indigo-500"> Regex
            </label>
            <button onclick="TrafficTab.doSearch()" class="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded">Go</button>
            <button onclick="TrafficTab.clearSearch()" class="text-xs text-gray-400 hover:text-white px-2 py-1">Clear</button>
          </div>
          <div id="flow-rows"></div>
        </div>
        <div class="flow-detail w-1/2" id="flow-detail">
          ${FlowDetail.render(null)}
        </div>
      </div>`;
  },

  onFlowUpdate(flow) {
    this.flowMap[flow.id] = flow;
    const existing = this.flows.findIndex(f => f.id === flow.id);
    if (existing >= 0) {
      this.flows[existing] = flow;
    } else {
      this.flows.push(flow);
    }
    if (this.flows.length > 5000) {
      const removed = this.flows.splice(0, 1000);
      removed.forEach(f => delete this.flowMap[f.id]);
    }
    if (!this.searchMode) this.renderList();
    document.getElementById('flow-count').textContent = this.flows.length + ' flows';
    if (flow.id === this.selectedId) {
      document.getElementById('flow-detail').innerHTML = FlowDetail.render(flow);
    }
  },

  renderList(flowsOverride) {
    const container = document.getElementById('flow-rows');
    if (!container) return;
    const source = flowsOverride || this.flows;
    const filter = (document.getElementById('flow-filter')?.value || '').toLowerCase();
    const filtered = filter
      ? source.filter(f => (f.host + f.path + f.method + (f.flow_type||'')).toLowerCase().includes(filter))
      : source;
    const visible = filtered.slice(-500);
    container.innerHTML = visible.map(f => FlowRow.render(f, f.id === this.selectedId, this.highlightRules)).join('');
    if (this.autoScroll && !flowsOverride) {
      const list = document.getElementById('flow-list');
      if (list) list.scrollTop = list.scrollHeight;
    }
  },

  applyFilter() { this.renderList(); },

  selectFlow(id) {
    this.selectedId = id;
    const flow = this.flowMap[id];
    document.getElementById('flow-detail').innerHTML = FlowDetail.render(flow);
    this.renderList();
  },

  // ── Context menu ───────────────────────────────────────

  showContextMenu(e, id) {
    e.preventDefault();
    const menu = document.getElementById('ctx-menu');
    menu.innerHTML = `
      <div class="ctx-menu-item" onclick="TrafficTab.sendToReplay('${id}')">Send to Replay</div>
      <div class="ctx-menu-item" onclick="TrafficTab.copyCurl('${id}')">Copy as cURL</div>
      <div class="ctx-menu-item text-red-400" onclick="TrafficTab.deleteFlow('${id}')">Delete</div>
    `;
    menu.style.left = e.clientX + 'px';
    menu.style.top = e.clientY + 'px';
    menu.classList.remove('hidden');
    const hide = () => { menu.classList.add('hidden'); document.removeEventListener('click', hide); };
    setTimeout(() => document.addEventListener('click', hide), 10);
  },

  async sendToReplay(id) {
    const flow = this.flowMap[id];
    if (!flow) return;
    // Switch to replay tab with pre-filled data
    window._replayPrefill = {
      method: flow.method,
      url: flow.url,
      headers: flow.request_headers,
      body: flow.request_body,
    };
    document.querySelector('[data-tab="replay"]').click();
  },

  async copyCurl(id) {
    try {
      const resp = await fetch(`/api/flows/${id}/curl`);
      const data = await resp.json();
      await navigator.clipboard.writeText(data.curl);
      Toast.show('cURL copied to clipboard', 'success');
    } catch (e) {
      Toast.show('Failed to copy cURL', 'error');
    }
  },

  async deleteFlow(id) {
    try {
      await fetch(`/api/flows/${id}`, { method: 'DELETE' });
      this.flows = this.flows.filter(f => f.id !== id);
      delete this.flowMap[id];
      if (this.selectedId === id) {
        this.selectedId = null;
        document.getElementById('flow-detail').innerHTML = FlowDetail.render(null);
      }
      this.renderList();
    } catch (e) { Toast.show('Failed to delete', 'error'); }
  },

  // ── Search ─────────────────────────────────────────────

  toggleSearch() {
    const bar = document.getElementById('search-bar');
    bar.classList.toggle('hidden');
    if (!bar.classList.contains('hidden')) {
      document.getElementById('search-input').focus();
    } else {
      this.clearSearch();
    }
  },

  async doSearch() {
    const q = document.getElementById('search-input').value;
    const regex = document.getElementById('search-regex').checked;
    if (!q) { this.clearSearch(); return; }
    try {
      const resp = await fetch(`/api/flows/search?q=${encodeURIComponent(q)}&regex=${regex}`);
      const results = await resp.json();
      this.searchMode = true;
      results.forEach(f => this.flowMap[f.id] = f);
      this.renderList(results);
      Toast.show(`${results.length} results`, 'info');
    } catch (e) {
      Toast.show('Search failed', 'error');
    }
  },

  clearSearch() {
    this.searchMode = false;
    document.getElementById('search-input').value = '';
    this.renderList();
  },

  // ── Export / Import ────────────────────────────────────

  toggleExportMenu() {
    window.open('/api/flows/export/har', '_blank');
  },

  async importHAR(input) {
    const file = input.files[0];
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    try {
      const resp = await fetch('/api/flows/import/har', { method: 'POST', body: form });
      const data = await resp.json();
      Toast.show(`Imported ${data.imported} flows`, 'success');
      this.loadInitial();
    } catch (e) {
      Toast.show('Import failed', 'error');
    }
    input.value = '';
  },

  // ── Clear + Load ───────────────────────────────────────

  async clearFlows() {
    try {
      await fetch('/api/flows', { method: 'DELETE' });
      this.flows = [];
      this.flowMap = {};
      this.selectedId = null;
      this.renderList();
      document.getElementById('flow-detail').innerHTML = FlowDetail.render(null);
      document.getElementById('flow-count').textContent = '0 flows';
      Toast.show('Flows cleared', 'success');
    } catch (e) {
      Toast.show('Failed to clear flows', 'error');
    }
  },

  async loadInitial() {
    try {
      const resp = await fetch('/api/flows?limit=500');
      const flows = await resp.json();
      this.flows = [];
      this.flowMap = {};
      flows.reverse().forEach(f => {
        this.flowMap[f.id] = f;
        this.flows.push(f);
      });
      this.renderList();
      document.getElementById('flow-count').textContent = this.flows.length + ' flows';
    } catch (e) {
      console.warn('Failed to load initial flows:', e);
    }
    // Load highlight rules
    try {
      const resp = await fetch('/api/settings');
      const settings = await resp.json();
      this.highlightRules = settings.highlight_rules || [];
      if (!this.highlightRules.length) {
        // Default highlights
        this.highlightRules = [
          { enabled: true, match_type: 'content-type', pattern: 'image', color: '#4c1d95' },
          { enabled: true, match_type: 'content-type', pattern: 'json', color: '#064e3b' },
          { enabled: true, match_type: 'content-type', pattern: 'html', color: '#1e3a5f' },
          { enabled: true, match_type: 'status', pattern: '^5', color: '#7f1d1d' },
          { enabled: true, match_type: 'status', pattern: '^3', color: '#1e3a5f' },
        ];
      }
      this.renderList();
    } catch (e) { /* ignore */ }
  }
};

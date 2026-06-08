// Wait for dependencies to be available
async function waitForDependencies() {
  let attempts = 0;
  const maxAttempts = 50; // Wait up to 5 seconds

  while (typeof authFetch === 'undefined' && attempts < maxAttempts) {
    await new Promise(resolve => setTimeout(resolve, 100));
    attempts++;
  }

  if (typeof authFetch === 'undefined') {
    throw new Error('authFetch failed to load after 5 seconds');
  }
}

// Traffic tab: virtual scroll, sort, compare, bookmarks, search, export/import
window.TrafficTab = {
  flows: [],
  flowMap: {},
  selectedId: null,
  autoScroll: true,
  searchMode: false,
  highlightRules: [],
  sortField: null,     // null, 'method', 'status', 'host', 'duration', 'size'
  sortDir: 'asc',
  compareId: null,      // second flow ID for compare mode
  savedFilters: JSON.parse(localStorage.getItem('pRoxy-filters') || '[]'),

  // Virtual scroll config
  ROW_HEIGHT: 32,
  BUFFER_ROWS: 20,
  _filteredFlows: [],
  _scrollTop: 0,

  render() {
    const filterOptions = this.savedFilters.length
      ? `<select id="saved-filter-select" onchange="TrafficTab.loadSavedFilter(this.value)" class="bg-gray-800 text-gray-300 text-xs px-1 py-1 rounded border border-gray-700 w-20">
           <option value="">Saved</option>
           ${this.savedFilters.map((f, i) => `<option value="${i}">${esc(f.name)}</option>`).join('')}
         </select>`
      : '';
    return `
      <div class="split-pane">
        <div class="flow-list w-1/2 min-w-[300px] flex flex-col" id="flow-list">
          <div class="flex items-center justify-between px-3 py-2 bg-gray-900 border-b border-gray-800 sticky top-0 z-10">
            <div class="flex items-center gap-2">
              <input type="text" id="flow-filter" placeholder="Filter..."
                class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 w-28 focus:outline-none focus:border-indigo-500"
                oninput="TrafficTab._debouncedFilter()">
              <button onclick="TrafficTab.saveCurrentFilter()" class="text-xs text-gray-500 hover:text-white px-1 py-1" title="Save filter">+</button>
              ${filterOptions}
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
          <!-- Sort headers -->
          <div class="flex items-center px-3 py-1 bg-gray-900/50 border-b border-gray-800 text-xs text-gray-500">
            <span class="w-14 shrink-0 sort-header ${this._sortClass('method')}" onclick="TrafficTab.toggleSort('method')">Method</span>
            <span class="w-10 shrink-0 sort-header ${this._sortClass('status')}" onclick="TrafficTab.toggleSort('status')">Status</span>
            <span class="flex-1 sort-header ${this._sortClass('host')}" onclick="TrafficTab.toggleSort('host')">Host / Path</span>
            <span class="w-14 shrink-0 text-right sort-header ${this._sortClass('size')}" onclick="TrafficTab.toggleSort('size')">Size</span>
            <span class="w-14 shrink-0 text-right sort-header ${this._sortClass('duration')}" onclick="TrafficTab.toggleSort('duration')">Time</span>
          </div>
          <!-- Virtual scroll container -->
          <div id="flow-scroll" class="virtual-scroll-container flex-1" onscroll="TrafficTab._onScroll()">
            <div id="flow-spacer" class="virtual-scroll-spacer"></div>
            <div id="flow-rows" class="virtual-scroll-content"></div>
          </div>
        </div>
        <div class="flow-detail w-1/2" id="flow-detail">
          ${FlowDetail.render(null)}
        </div>
      </div>`;
  },

  // ── Debounced filter ──────────────────────────────────────
  _debouncedFilter: debounce(function() { TrafficTab.applyFilter(); }, 150),

  // ── Sort ──────────────────────────────────────────────────

  _sortClass(field) {
    if (this.sortField !== field) return '';
    return this.sortDir === 'asc' ? 'sort-asc' : 'sort-desc';
  },

  toggleSort(field) {
    if (this.sortField === field) {
      if (this.sortDir === 'asc') this.sortDir = 'desc';
      else { this.sortField = null; this.sortDir = 'asc'; }
    } else {
      this.sortField = field;
      this.sortDir = 'asc';
    }
    this._updateFiltered();
    this.renderList();
    // Re-render sort headers
    const headerRow = document.querySelector('#flow-list .sort-header')?.parentElement;
    if (headerRow) {
      headerRow.innerHTML = `
        <span class="w-14 shrink-0 sort-header ${this._sortClass('method')}" onclick="TrafficTab.toggleSort('method')">Method</span>
        <span class="w-10 shrink-0 sort-header ${this._sortClass('status')}" onclick="TrafficTab.toggleSort('status')">Status</span>
        <span class="flex-1 sort-header ${this._sortClass('host')}" onclick="TrafficTab.toggleSort('host')">Host / Path</span>
        <span class="w-14 shrink-0 text-right sort-header ${this._sortClass('size')}" onclick="TrafficTab.toggleSort('size')">Size</span>
        <span class="w-14 shrink-0 text-right sort-header ${this._sortClass('duration')}" onclick="TrafficTab.toggleSort('duration')">Time</span>`;
    }
  },

  _sortFlows(flows) {
    if (!this.sortField) return flows;
    const dir = this.sortDir === 'asc' ? 1 : -1;
    const field = this.sortField;
    return [...flows].sort((a, b) => {
      let va, vb;
      switch (field) {
        case 'method': va = a.method || ''; vb = b.method || ''; return va.localeCompare(vb) * dir;
        case 'status': va = a.status_code || 0; vb = b.status_code || 0; return (va - vb) * dir;
        case 'host': va = a.host || ''; vb = b.host || ''; return va.localeCompare(vb) * dir;
        case 'duration': va = a.duration_ms || 0; vb = b.duration_ms || 0; return (va - vb) * dir;
        case 'size': va = a.response_size || 0; vb = b.response_size || 0; return (va - vb) * dir;
        default: return 0;
      }
    });
  },

  // ── Virtual scroll ────────────────────────────────────────

  _updateFiltered(flowsOverride) {
    const source = flowsOverride || this.flows;
    const filter = (document.getElementById('flow-filter')?.value || '').toLowerCase();
    let filtered = filter
      ? source.filter(f => (f.host + f.path + f.method + (f.flow_type||'')).toLowerCase().includes(filter))
      : source;
    filtered = this._sortFlows(filtered);
    this._filteredFlows = filtered;
  },

  _onScroll() {
    const container = document.getElementById('flow-scroll');
    if (!container) return;
    this._scrollTop = container.scrollTop;
    this._renderVirtualRows();
  },

  _renderVirtualRows() {
    const container = document.getElementById('flow-scroll');
    const spacer = document.getElementById('flow-spacer');
    const content = document.getElementById('flow-rows');
    if (!container || !spacer || !content) return;

    const flows = this._filteredFlows;
    const totalHeight = flows.length * this.ROW_HEIGHT;
    spacer.style.height = totalHeight + 'px';

    const scrollTop = this._scrollTop;
    const viewHeight = container.clientHeight;
    const startIdx = Math.max(0, Math.floor(scrollTop / this.ROW_HEIGHT) - this.BUFFER_ROWS);
    const endIdx = Math.min(flows.length, Math.ceil((scrollTop + viewHeight) / this.ROW_HEIGHT) + this.BUFFER_ROWS);

    content.style.top = (startIdx * this.ROW_HEIGHT) + 'px';

    const visibleFlows = flows.slice(startIdx, endIdx);
    content.innerHTML = visibleFlows.map(f =>
      FlowRow.render(f, f.id === this.selectedId, this.highlightRules, f.id === this.compareId)
    ).join('');
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
    if (!this.searchMode) {
      this._updateFiltered();
      this.renderList();
    }
    document.getElementById('flow-count').textContent = this.flows.length + ' flows';
    if (flow.id === this.selectedId) {
      document.getElementById('flow-detail').innerHTML = FlowDetail.render(flow);
      // Auto-scroll WS message list to bottom on new messages
      const wsMsgContainer = document.getElementById('ws-messages');
      if (wsMsgContainer) wsMsgContainer.scrollTop = wsMsgContainer.scrollHeight;
    }
  },

  renderList(flowsOverride) {
    if (flowsOverride) {
      this._updateFiltered(flowsOverride);
    }
    this._renderVirtualRows();
    if (this.autoScroll && !flowsOverride && !this.sortField) {
      const container = document.getElementById('flow-scroll');
      if (container) {
        container.scrollTop = container.scrollHeight;
        this._scrollTop = container.scrollTop;
      }
    }
  },

  applyFilter() {
    this._updateFiltered();
    this.renderList();
  },

  selectFlow(id) {
    this.selectedId = id;
    const flow = this.flowMap[id];

    // If in compare mode and we already have a selected flow, show diff
    if (this.compareId && this.compareId !== id) {
      // Need full flow data for body comparison — fetch if needed
      this._fetchFullFlow(this.compareId).then(fullA => {
        this._fetchFullFlow(id).then(fullB => {
          document.getElementById('flow-detail').innerHTML = FlowDetail.renderDiff(fullA, fullB);
        });
      });
      this._renderVirtualRows();
      return;
    }

    // Fetch full flow data (with body) for detail view
    this._fetchFullFlow(id).then(fullFlow => {
      document.getElementById('flow-detail').innerHTML = FlowDetail.render(fullFlow || flow);
    });
    this._renderVirtualRows();
  },

  async _fetchFullFlow(id) {
    const cached = this.flowMap[id];
    // If we already have the body, no need to fetch
    if (cached && (cached.response_body !== undefined && cached.response_body !== null)) {
      return cached;
    }
    try {
      const resp = await authFetch(`/api/flows/${id}`);
      if (!resp.ok) return cached;
      const full = await resp.json();
      this.flowMap[id] = full;
      return full;
    } catch {
      return cached;
    }
  },

  // ── Compare / Diff ────────────────────────────────────────

  toggleCompare(id) {
    if (this.compareId === id) {
      this.exitCompare();
    } else {
      this.compareId = id;
      Toast.show('Select another flow to compare', 'info');
      this._renderVirtualRows();
    }
  },

  exitCompare() {
    this.compareId = null;
    const flow = this.selectedId ? this.flowMap[this.selectedId] : null;
    document.getElementById('flow-detail').innerHTML = FlowDetail.render(flow);
    this._renderVirtualRows();
  },

  // ── Context menu ───────────────────────────────────────

  showContextMenu(e, id) {
    e.preventDefault();
    const menu = document.getElementById('ctx-menu');
    menu.innerHTML = `
      <div class="ctx-menu-item" onclick="TrafficTab.sendToReplay('${id}')">Send to Replay</div>
      <div class="ctx-menu-item" onclick="TrafficTab.sendToStress('${id}')">Send to Stress Test</div>
      <div class="ctx-menu-item" onclick="TrafficTab.sendToOffensive('${id}')">Send to Offensive</div>
      <div class="ctx-menu-item" onclick="TrafficTab.copyCurl('${id}')">Copy as cURL</div>
      <div class="ctx-menu-item" onclick="TrafficTab.toggleCompare('${id}')">Compare</div>
      <div class="ctx-menu-item text-red-400" onclick="TrafficTab.deleteFlow('${id}')">Delete</div>
    `;
    menu.style.left = e.clientX + 'px';
    menu.style.top = e.clientY + 'px';
    menu.classList.remove('hidden');
    const hide = () => { menu.classList.add('hidden'); document.removeEventListener('click', hide); };
    setTimeout(() => document.addEventListener('click', hide), 10);
  },

  async sendToReplay(id) {
    const flow = await this._fetchFullFlow(id);
    if (!flow) return;
    window._replayPrefill = {
      method: flow.method,
      url: flow.url,
      headers: flow.request_headers,
      body: flow.request_body,
      _originalResponse: {
        status_code: flow.status_code,
        response_body: flow.response_body,
        response_headers: flow.response_headers,
        duration_ms: flow.duration_ms,
      },
    };
    document.querySelector('[data-tab="replay"]').click();
  },

  async sendToOffensive(id) {
    window._offensivePrefill = { flowId: id };
    document.querySelector('[data-tab="offensive"]').click();
  },

  async sendToStress(id) {
    const flow = await this._fetchFullFlow(id);
    if (!flow) return;
    window._stressPrefill = {
      method: flow.method,
      url: flow.url,
      headers: flow.request_headers || {},
      body: flow.request_body || '',
    };
    document.querySelector('[data-tab="tools"]').click();
  },

  async copyCurl(id) {
    try {
      const resp = await authFetch(`/api/flows/${id}/curl`);
      if (!resp.ok) { Toast.show('Failed to get cURL', 'error'); return; }
      const data = await resp.json();
      await copyToClipboard(data.curl);
      Toast.show('cURL copied to clipboard', 'success');
    } catch (e) {
      Toast.show('Failed to copy cURL', 'error');
    }
  },

  async deleteFlow(id) {
    try {
      await authFetch(`/api/flows/${id}`, { method: 'DELETE' });
      this.flows = this.flows.filter(f => f.id !== id);
      delete this.flowMap[id];
      if (this.selectedId === id) {
        this.selectedId = null;
        document.getElementById('flow-detail').innerHTML = FlowDetail.render(null);
      }
      if (this.compareId === id) this.compareId = null;
      this._updateFiltered();
      this.renderList();
    } catch (e) { Toast.show('Failed to delete', 'error'); }
  },

  // ── Keyboard navigation ──────────────────────────────────

  navigateFlow(direction) {
    const flows = this._filteredFlows;
    if (!flows.length) return;
    const currentIdx = flows.findIndex(f => f.id === this.selectedId);
    let nextIdx;
    if (direction === 'up') {
      nextIdx = currentIdx <= 0 ? 0 : currentIdx - 1;
    } else {
      nextIdx = currentIdx >= flows.length - 1 ? flows.length - 1 : currentIdx + 1;
    }
    this.selectFlow(flows[nextIdx].id);
    // Scroll into view
    const container = document.getElementById('flow-scroll');
    if (container) {
      const targetTop = nextIdx * this.ROW_HEIGHT;
      if (targetTop < container.scrollTop) {
        container.scrollTop = targetTop;
      } else if (targetTop + this.ROW_HEIGHT > container.scrollTop + container.clientHeight) {
        container.scrollTop = targetTop + this.ROW_HEIGHT - container.clientHeight;
      }
      this._scrollTop = container.scrollTop;
      this._renderVirtualRows();
    }
  },

  // ── Saved filters / bookmarks ────────────────────────────

  saveCurrentFilter() {
    const filter = document.getElementById('flow-filter')?.value;
    if (!filter) { Toast.show('Enter a filter first', 'warn'); return; }
    const name = prompt('Filter name:', filter);
    if (!name) return;
    this.savedFilters.push({ name, value: filter });
    localStorage.setItem('pRoxy-filters', JSON.stringify(this.savedFilters));
    Toast.show('Filter saved', 'success');
  },

  loadSavedFilter(idx) {
    if (idx === '') return;
    const f = this.savedFilters[parseInt(idx)];
    if (!f) return;
    const el = document.getElementById('flow-filter');
    if (el) { el.value = f.value; this.applyFilter(); }
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
      const resp = await authFetch(`/api/flows/search?q=${encodeURIComponent(q)}&regex=${regex}`);
      if (!resp.ok) { Toast.show('Search failed', 'error'); return; }
      const results = await resp.json();
      this.searchMode = true;
      results.forEach(f => this.flowMap[f.id] = f);
      this._updateFiltered(results);
      this.renderList(results);
      Toast.show(`${results.length} results`, 'info');
    } catch (e) {
      Toast.show('Search failed', 'error');
    }
  },

  clearSearch() {
    this.searchMode = false;
    document.getElementById('search-input').value = '';
    this._updateFiltered();
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
      const resp = await authFetch('/api/flows/import/har', { method: 'POST', body: form });
      if (!resp.ok) { Toast.show('Import failed', 'error'); return; }
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
    // Prevent multiple simultaneous clear operations
    if (this._clearing) {
      return;
    }

    try {
      this._clearing = true;
      const flowsBeforeClear = this.flows.length;

      // Wait for dependencies to load
      await waitForDependencies();

      const response = await authFetch('/api/flows', {
        method: 'DELETE',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });


      if (!response.ok) {
        const errorText = await response.text().catch(() => 'Unknown error');
        throw new Error(`Clear failed with status: ${response.status} ${response.statusText}. ${errorText}`);
      }

      // Parse the response to get deletion count
      let result;
      try {
        const responseText = await response.text();

        if (!responseText.trim()) {
          throw new Error('Empty response from server');
        }

        result = JSON.parse(responseText);

        if (typeof result !== 'object' || result === null) {
          throw new Error('Invalid response format');
        }

        if (!('deleted' in result)) {
            result = { deleted: 0 };
        }

      } catch (parseError) {
        console.error('Failed to parse JSON response:', parseError);
        // Fallback: assume success if we got a 200 status
        result = { deleted: flowsBeforeClear };
      }

      // Clear local state immediately to provide responsive UX

      this.flows = [];
      this.flowMap = {};
      this.selectedId = null;
      this.compareId = null;
      this._filteredFlows = [];
      this.renderList();

      const flowDetailEl = document.getElementById('flow-detail');
      if (flowDetailEl) {
        flowDetailEl.innerHTML = FlowDetail.render(null);
      }

      const flowCountEl = document.getElementById('flow-count');
      if (flowCountEl) {
        flowCountEl.textContent = '0 flows';
      }

      // Show success message with count
      const deletedCount = result.deleted || 0;

      const message = deletedCount > 0
        ? `${deletedCount} flows cleared`
        : 'Flows cleared';

      Toast.show(message, 'success');

      // Force a reload of flows to verify clear was successful
      setTimeout(() => {
        this.loadInitial().catch(e => {
          console.warn('Failed to reload flows after clear:', e);
        });
      }, 100);

    } catch (e) {
      console.error('Clear flows error details:', {
        error: e,
        message: e.message,
        stack: e.stack,
        name: e.name
      });



      // Always clear local state even if backend call failed
      // This provides better UX and handles cases where backend succeeded but response failed
      const flowsBeforeClear = this.flows.length;
      if (flowsBeforeClear > 0) {
        this.flows = [];
        this.flowMap = {};
        this.selectedId = null;
        this.compareId = null;
        this._filteredFlows = [];
        this.renderList();

        const flowDetailEl = document.getElementById('flow-detail');
        if (flowDetailEl) {
          flowDetailEl.innerHTML = FlowDetail.render(null);
        }

        const flowCountEl = document.getElementById('flow-count');
        if (flowCountEl) {
          flowCountEl.textContent = '0 flows';
        }
      }

      // Show more user-friendly error messages
      let errorMessage = 'Failed to clear flows';

      if (e.name === 'TypeError' && e.message.includes('fetch')) {
        errorMessage = 'Network error - check connection';
      } else if (e.message.includes('timeout')) {
        errorMessage = 'Request timed out - flows may have been cleared';
      } else if (e.message.includes('parse')) {
        errorMessage = 'Server response error - flows may have been cleared';
      }

      Toast.show(errorMessage, 'error');

      // Force reload to check actual state after error
      setTimeout(() => {
        this.loadInitial().catch(e => {
          console.warn('Failed to reload flows after error:', e);
        });
      }, 500);

    } finally {
      this._clearing = false;
    }
  },

  async loadInitial() {
    try {
      // Wait for dependencies to load
      await waitForDependencies();

      const resp = await authFetch('/api/flows/lite?limit=500');
      if (!resp.ok) throw new Error('Failed to load');
      const flows = await resp.json();
      this.flows = [];
      this.flowMap = {};
      flows.reverse().forEach(f => {
        this.flowMap[f.id] = f;
        this.flows.push(f);
      });
      this._updateFiltered();
      this.renderList();
      document.getElementById('flow-count').textContent = this.flows.length + ' flows';
    } catch (e) {
      console.warn('Failed to load initial flows:', e);
    }
    // Load highlight rules
    try {
      const resp = await authFetch('/api/settings');
      if (!resp.ok) throw new Error('Failed to load settings');
      const settings = await resp.json();
      this.highlightRules = settings.highlight_rules || [];
      if (!this.highlightRules.length) {
        this.highlightRules = [
          { enabled: true, match_type: 'content-type', pattern: 'image', color: '#4c1d95' },
          { enabled: true, match_type: 'content-type', pattern: 'json', color: '#064e3b' },
          { enabled: true, match_type: 'content-type', pattern: 'html', color: '#1e3a5f' },
          { enabled: true, match_type: 'status', pattern: '^5', color: '#7f1d1d' },
          { enabled: true, match_type: 'status', pattern: '^3', color: '#1e3a5f' },
        ];
      }
      this._renderVirtualRows();
    } catch (e) { /* ignore */ }
  }
};

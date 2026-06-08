// Unified Issues dashboard — aggregates scanner, recon, and threat_detection
// findings into one prioritized view. Read-only: it only renders what the
// /api/issues endpoint already computed.
const IssuesTab = {
  data: null,

  SEV_COLORS: {
    critical: 'bg-red-900 text-red-300 border-red-700',
    high: 'bg-orange-900 text-orange-300 border-orange-700',
    medium: 'bg-yellow-900 text-yellow-300 border-yellow-700',
    low: 'bg-blue-900 text-blue-300 border-blue-700',
    info: 'bg-gray-800 text-gray-400 border-gray-700',
  },

  SEV_ORDER: ['critical', 'high', 'medium', 'low', 'info'],

  SOURCE_COLORS: {
    scanner: 'bg-indigo-900 text-indigo-300',
    recon: 'bg-teal-900 text-teal-300',
    threat_detection: 'bg-rose-900 text-rose-300',
  },

  render() {
    return `
      <div class="p-4 space-y-4">
        <div>
          <h2 class="text-lg font-bold text-white mb-1">Issues</h2>
          <p class="text-xs text-gray-500">Unified, prioritized view of findings from the scanner, recon, and threat-detection engines over captured traffic.</p>
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Domain filter (substring of host)</label>
            <input id="issues-domain" class="bg-gray-900 text-gray-200 text-xs px-3 py-2 rounded border border-gray-700 focus:outline-none focus:border-indigo-500" placeholder="e.g. api.example.com" style="width:280px">
          </div>
          <button onclick="IssuesTab.load()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-2 rounded">Refresh</button>
        </div>

        <div id="issues-summary" class="flex flex-wrap gap-2"></div>

        <div id="issues-list" class="space-y-2">
          <div class="text-gray-500 text-xs">Click "Refresh" to aggregate findings from captured traffic.</div>
        </div>
      </div>`;
  },

  _domain() { return (document.getElementById('issues-domain')?.value || '').trim(); },

  _sevBadge(sev) {
    const c = this.SEV_COLORS[sev] || this.SEV_COLORS.info;
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${c}">${esc(sev)}</span>`;
  },

  _sourceTag(src) {
    const c = this.SOURCE_COLORS[src] || 'bg-gray-800 text-gray-400';
    return `<span class="px-2 py-0.5 rounded text-[10px] font-mono ${c}">${esc(src)}</span>`;
  },

  _renderSummary() {
    const el = document.getElementById('issues-summary');
    if (!el) return;
    const d = this.data;
    if (!d) { el.innerHTML = ''; return; }
    const bySev = d.by_severity || {};
    const chips = this.SEV_ORDER.map(sev => {
      const count = bySev[sev] || 0;
      const c = this.SEV_COLORS[sev] || this.SEV_COLORS.info;
      const dim = count ? '' : 'opacity-40';
      return `<div class="flex items-center gap-2 px-3 py-1.5 rounded border ${c} ${dim}">
                <span class="text-[10px] font-bold uppercase">${esc(sev)}</span>
                <span class="text-sm font-bold">${count}</span>
              </div>`;
    }).join('');
    const total = `<div class="flex items-center gap-2 px-3 py-1.5 rounded border border-gray-700 bg-gray-900 text-gray-300">
                     <span class="text-[10px] font-bold uppercase">Total</span>
                     <span class="text-sm font-bold">${d.total || 0}</span>
                   </div>`;
    el.innerHTML = total + chips;
  },

  _renderList() {
    const el = document.getElementById('issues-list');
    if (!el) return;
    const issues = (this.data && this.data.issues) || [];
    if (!issues.length) {
      el.innerHTML = '<div class="text-gray-500 text-xs">No issues found for this filter. Capture more traffic or run the scanner/recon engines first.</div>';
      return;
    }
    el.innerHTML = issues.map(i => `
      <div class="bg-gray-900 rounded border border-gray-800 p-3">
        <div class="flex items-center gap-2 mb-1">
          ${this._sevBadge(i.severity)}
          ${this._sourceTag(i.source)}
          <span class="text-sm font-semibold text-white">${esc(i.title || '')}</span>
        </div>
        ${i.detail ? `<div class="text-xs text-gray-400 mb-1">${esc(i.detail)}</div>` : ''}
        ${i.location ? `<div class="text-[11px] text-gray-600 font-mono">${esc(i.location)}</div>` : ''}
      </div>`).join('');
  },

  async load() {
    const list = document.getElementById('issues-list');
    if (list) list.innerHTML = '<div class="text-gray-500 text-xs">Aggregating findings…</div>';
    try {
      const resp = await authFetch('/api/issues?domain=' + encodeURIComponent(this._domain()));
      this.data = await resp.json();
      this._renderSummary();
      this._renderList();
      Toast.show(`Found ${this.data.total || 0} issue(s)`, this.data.total ? 'info' : 'success');
    } catch (e) {
      if (list) list.innerHTML = '<div class="text-red-400 text-xs">Error: ' + esc(e.message) + '</div>';
      Toast.show('Failed to load issues: ' + e.message, 'error');
    }
  },
};

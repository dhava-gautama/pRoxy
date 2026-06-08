// DNS tab: DoH toggle, blocklist, custom mappings
window.DNSTab = {
  dns: null,

  _input: 'bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500',
  _btn: 'bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded',
  _btnSm: 'bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs px-2 py-1 rounded',

  _providers: [
    { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
    { name: 'Google', url: 'https://dns.google/resolve' },
    { name: 'Quad9', url: 'https://dns.quad9.net:5053/dns-query' },
    { name: 'AdGuard', url: 'https://dns.adguard-dns.com/dns-query' },
    { name: 'Mullvad', url: 'https://dns.mullvad.net/dns-query' },
    { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query' },
    { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query' },
    { name: 'Comodo', url: 'https://doh.dns.sb/dns-query' },
  ],

  render() {
    const providerOpts = this._providers.map(p =>
      `<option value="${p.url}">${p.name}</option>`
    ).join('');

    return `
      <div class="max-w-3xl mx-auto p-6 space-y-6">
        <h2 class="text-lg font-bold text-white">DNS Configuration</h2>

        <div id="dns-loading" class="text-gray-500">Loading DNS settings...</div>
        <div id="dns-content" class="hidden space-y-6">

          <!-- DoH -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <div>
                <span class="text-gray-200 text-sm">DNS over HTTPS</span>
                <span class="text-gray-500 text-xs ml-2">Route DNS through encrypted HTTPS</span>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="doh-toggle" onchange="DNSTab.toggleDoH(this.checked)">
                <span class="toggle-slider"></span>
              </label>
            </div>
            <div class="flex gap-2 items-center">
              <select id="doh-provider" onchange="DNSTab.pickProvider(this.value)"
                class="${this._input} w-36 cursor-pointer">
                <option value="">Provider...</option>
                ${providerOpts}
                <option value="custom">Custom</option>
              </select>
              <input id="doh-url" type="text" placeholder="DoH URL"
                class="flex-1 ${this._input}">
              <button onclick="DNSTab.saveDoHUrl()" class="${this._btn}">Save</button>
            </div>
          </div>

          <!-- Blocklist -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-bold text-gray-400 uppercase">Domain Blocklist</h3>
              <button onclick="DNSTab.showForm('block')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="block-form" class="hidden"></div>
            <div id="blocklist" class="space-y-1"></div>
          </div>

          <!-- Custom Mappings -->
          <div class="bg-gray-900 rounded-lg p-4 space-y-3">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-bold text-gray-400 uppercase">Custom DNS Mappings</h3>
              <button onclick="DNSTab.showForm('mapping')" class="text-xs ${this._btn}">+ Add</button>
            </div>
            <div id="mapping-form" class="hidden"></div>
            <div id="dns-mappings" class="space-y-1"></div>
          </div>

        </div>
      </div>`;
  },

  showForm(type) {
    const el = document.getElementById(type + '-form');
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }
    const I = this._input;
    const forms = {
      block: `<div class="flex gap-2 items-end bg-gray-800/50 rounded p-3">
        <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Domain to block</label>
        <input id="f-block-domain" class="w-full ${I}" placeholder="ads.example.com"
          onkeydown="if(event.key==='Enter')DNSTab.submitBlock()"></div>
        <button onclick="DNSTab.submitBlock()" class="${this._btn}">Add</button>
        <button onclick="DNSTab.hideForm('block')" class="${this._btnSm}">Cancel</button>
      </div>`,
      mapping: `<div class="flex gap-2 items-end bg-gray-800/50 rounded p-3">
        <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">Hostname</label>
        <input id="f-map-hostname" class="w-full ${I}" placeholder="api.example.com"
          onkeydown="if(event.key==='Enter')DNSTab.submitMapping()"></div>
        <div class="flex-1"><label class="text-xs text-gray-500 block mb-1">IP address</label>
        <input id="f-map-ip" class="w-full ${I}" placeholder="127.0.0.1"
          onkeydown="if(event.key==='Enter')DNSTab.submitMapping()"></div>
        <button onclick="DNSTab.submitMapping()" class="${this._btn}">Add</button>
        <button onclick="DNSTab.hideForm('mapping')" class="${this._btnSm}">Cancel</button>
      </div>`,
    };
    el.innerHTML = forms[type] || '';
    el.classList.remove('hidden');
    const firstInput = el.querySelector('input');
    if (firstInput) firstInput.focus();
  },

  hideForm(type) {
    document.getElementById(type + '-form').classList.add('hidden');
  },

  async load() {
    try {
      const resp = await authFetch('/api/dns');
      if (!resp.ok) { Toast.show('Failed to load DNS settings', 'error'); return; }
      this.dns = await resp.json();
      document.getElementById('dns-loading').classList.add('hidden');
      document.getElementById('dns-content').classList.remove('hidden');
      document.getElementById('doh-toggle').checked = this.dns.doh_enabled;
      document.getElementById('doh-url').value = this.dns.doh_url || '';
      this._syncProviderDropdown();
      this.renderBlocklist();
      this.renderMappings();
    } catch (e) {
      Toast.show('Failed to load DNS settings', 'error');
    }
  },

  async save(patch) {
    try {
      const resp = await authFetch('/api/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch)
      });
      this.dns = await resp.json();
    } catch (e) {
      Toast.show('Failed to update DNS', 'error');
    }
  },

  toggleDoH(enabled) { this.save({ doh_enabled: enabled }); },

  pickProvider(url) {
    const input = document.getElementById('doh-url');
    if (url === 'custom') {
      input.value = '';
      input.focus();
    } else if (url) {
      input.value = url;
      this.saveDoHUrl();
    }
  },

  _syncProviderDropdown() {
    const select = document.getElementById('doh-provider');
    if (!select) return;
    const url = (this.dns.doh_url || '').trim();
    const match = this._providers.find(p => p.url === url);
    select.value = match ? match.url : (url ? 'custom' : '');
  },

  saveDoHUrl() {
    this.save({ doh_url: document.getElementById('doh-url').value }).then(() => {
      this._syncProviderDropdown();
    });
  },

  renderBlocklist() {
    const list = this.dns.blocklist || [];
    document.getElementById('blocklist').innerHTML = list.length === 0
      ? '<div class="text-gray-600 text-xs">No blocked domains</div>'
      : list.map((d, i) => `
        <div class="flex items-center justify-between bg-gray-800 rounded px-3 py-1.5 text-xs">
          <span class="text-red-400">${esc(d)}</span>
          <button onclick="DNSTab.removeBlock(${i})" class="text-red-400 hover:text-red-300">✕</button>
        </div>
      `).join('');
  },

  submitBlock() {
    const domain = document.getElementById('f-block-domain').value.trim();
    if (!domain) return;
    const list = [...(this.dns.blocklist || []), domain];
    this.save({ blocklist: list }).then(() => {
      this.renderBlocklist();
      this.hideForm('block');
    });
  },

  removeBlock(index) {
    const list = this.dns.blocklist.filter((_, i) => i !== index);
    this.save({ blocklist: list }).then(() => this.renderBlocklist());
  },

  renderMappings() {
    const maps = this.dns.custom_mappings || [];
    document.getElementById('dns-mappings').innerHTML = maps.length === 0
      ? '<div class="text-gray-600 text-xs">No custom mappings</div>'
      : maps.map((m, i) => `
        <div class="flex items-center gap-2 bg-gray-800 rounded px-3 py-1.5 text-xs">
          <label class="toggle-switch" style="width:36px;height:20px">
            <input type="checkbox" ${m.enabled ? 'checked' : ''} onchange="DNSTab.toggleMapping(${i}, this.checked)">
            <span class="toggle-slider" style="border-radius:10px"></span>
          </label>
          <span class="text-indigo-400">${esc(m.hostname)}</span>
          <span class="text-gray-500">→</span>
          <span class="text-green-400">${esc(m.ip)}</span>
          <button onclick="DNSTab.removeMapping(${i})" class="ml-auto text-red-400 hover:text-red-300">✕</button>
        </div>
      `).join('');
  },

  submitMapping() {
    const hostname = document.getElementById('f-map-hostname').value.trim();
    const ip = document.getElementById('f-map-ip').value.trim();
    if (!hostname || !ip) return;
    const maps = [...(this.dns.custom_mappings || []), { hostname, ip, enabled: true }];
    this.save({ custom_mappings: maps }).then(() => {
      this.renderMappings();
      this.hideForm('mapping');
    });
  },

  toggleMapping(index, enabled) {
    const maps = [...this.dns.custom_mappings];
    maps[index] = { ...maps[index], enabled };
    this.save({ custom_mappings: maps }).then(() => this.renderMappings());
  },

  removeMapping(index) {
    const maps = this.dns.custom_mappings.filter((_, i) => i !== index);
    this.save({ custom_mappings: maps }).then(() => this.renderMappings());
  }
};

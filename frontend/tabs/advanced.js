// Advanced Proxy Features: HTTP/2, SSL/TLS, WebSocket enhancements, and custom protocols
window.AdvancedTab = {
  protocolConfig: null,
  sslInfo: null,
  websocketConfig: null,
  activeWebSockets: [],
  modifications: [],
  _selectedModification: null,

  _input: 'bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:outline-none focus:border-indigo-500',
  _btn: 'bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded',
  _btnSm: 'bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs px-2 py-1 rounded',

  render() {
    return `
      <div class="max-w-6xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-white">Advanced Proxy Features</h2>
          <div class="flex gap-2">
            <button onclick="AdvancedTab.detectProtocols()" class="text-xs bg-purple-600 hover:bg-purple-500 text-white px-3 py-1.5 rounded">
              🔍 Detect Protocols
            </button>
            <button onclick="AdvancedTab.showProtocolStats()" class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded">
              📊 Statistics
            </button>
          </div>
        </div>

        <!-- Protocol Configuration -->
        <div class="bg-gray-900 rounded-lg p-4 space-y-4">
          <h3 class="text-sm font-bold text-gray-400 uppercase">Protocol Support</h3>
          <div id="protocol-config" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>
          <div class="flex gap-2">
            <button onclick="AdvancedTab.saveProtocolConfig()" class="${this._btn}">Save Configuration</button>
          </div>
        </div>

        <!-- SSL/TLS Management -->
        <div class="bg-gray-900 rounded-lg p-4 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-gray-400 uppercase">SSL/TLS Management</h3>
            <div class="flex gap-2">
              <button onclick="AdvancedTab.downloadCertificate('pem')" class="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded">
                📄 PEM
              </button>
              <button onclick="AdvancedTab.downloadCertificate('android')" class="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded">
                📱 Android
              </button>
              <button onclick="AdvancedTab.regenerateCertificates()" class="text-xs bg-orange-600 hover:bg-orange-500 text-white px-2 py-1 rounded">
                🔄 Regenerate
              </button>
            </div>
          </div>
          <div id="ssl-info" class="space-y-2"></div>
        </div>

        <!-- WebSocket Enhancements -->
        <div class="bg-gray-900 rounded-lg p-4 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-gray-400 uppercase">WebSocket Enhancements</h3>
            <button onclick="AdvancedTab.refreshWebSockets()" class="text-xs ${this._btnSm}">🔄 Refresh</button>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <h4 class="text-xs font-semibold text-gray-300 mb-2">Configuration</h4>
              <div id="websocket-config" class="space-y-2"></div>
              <button onclick="AdvancedTab.saveWebSocketConfig()" class="mt-2 ${this._btnSm}">Save Config</button>
            </div>
            <div>
              <h4 class="text-xs font-semibold text-gray-300 mb-2">Active Connections</h4>
              <div id="active-websockets" class="space-y-1 max-h-40 overflow-y-auto"></div>
            </div>
          </div>
        </div>

        <!-- Custom Protocol Analysis -->
        <div class="bg-gray-900 rounded-lg p-4 space-y-4">
          <h3 class="text-sm font-bold text-gray-400 uppercase">Protocol Analysis</h3>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="space-y-2">
              <h4 class="text-xs font-semibold text-gray-300">GraphQL Schemas</h4>
              <div id="graphql-schemas" class="bg-gray-800 rounded p-2 text-xs max-h-32 overflow-y-auto">
                <div class="text-gray-500">No GraphQL schemas detected</div>
              </div>
            </div>

            <div class="space-y-2">
              <h4 class="text-xs font-semibold text-gray-300">gRPC Services</h4>
              <div id="grpc-services" class="bg-gray-800 rounded p-2 text-xs max-h-32 overflow-y-auto">
                <div class="text-gray-500">No gRPC services detected</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Advanced Request/Response Modifications -->
        <div class="bg-gray-900 rounded-lg p-4 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-gray-400 uppercase">Advanced Modifications</h3>
            <div class="flex gap-2">
              <button onclick="AdvancedTab.showModificationTemplates()" class="text-xs bg-purple-600 hover:bg-purple-500 text-white px-2 py-1 rounded">
                📋 Templates
              </button>
              <button onclick="AdvancedTab.createModification()" class="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded">
                ➕ New
              </button>
            </div>
          </div>
          <div id="modifications-list" class="space-y-2"></div>
        </div>

        <!-- Modification Templates Modal -->
        <div id="templates-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Modification Templates</h3>
              <button onclick="document.getElementById('templates-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
            </div>
            <div id="templates-content" class="space-y-4"></div>
          </div>
        </div>

        <!-- Modification Editor Modal -->
        <div id="editor-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Modification Editor</h3>
              <button onclick="document.getElementById('editor-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
            </div>
            <div id="editor-content" class="space-y-4"></div>
          </div>
        </div>

        <!-- Protocol Statistics Modal -->
        <div id="stats-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="this.classList.add('hidden')">
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-4xl max-h-[80vh] overflow-y-auto" onclick="event.stopPropagation()">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-white font-bold text-lg">Protocol Statistics</h3>
              <button onclick="document.getElementById('stats-modal').classList.add('hidden')" class="text-gray-400 hover:text-white">✕</button>
            </div>
            <div id="stats-content" class="space-y-4"></div>
          </div>
        </div>

      </div>`;
  },

  async load() {
    console.log('AdvancedTab.load() called');

    // Load each section individually with error handling
    try {
      await this.loadProtocolConfig();
    } catch (e) {
      console.error('Failed to load protocol config:', e);
    }

    try {
      await this.loadSSLInfo();
    } catch (e) {
      console.error('Failed to load SSL info:', e);
    }

    try {
      await this.loadWebSocketConfig();
    } catch (e) {
      console.error('Failed to load WebSocket config:', e);
    }

    try {
      await this.loadModifications();
    } catch (e) {
      console.error('Failed to load modifications:', e);
    }

    try {
      await this.loadProtocolAnalysis();
    } catch (e) {
      console.error('Failed to load protocol analysis:', e);
    }

    console.log('AdvancedTab.load() completed');
  },

  // ── Protocol Configuration ─────────────────────────────────────────

  async loadProtocolConfig() {
    try {
      const resp = await authFetch('/api/proxy/protocols');
      if (resp.ok) {
        this.protocolConfig = await resp.json();
        this.renderProtocolConfig();
      } else {
        console.warn('Protocol config API returned:', resp.status);
        this.renderProtocolConfigDefault();
      }
    } catch (e) {
      console.error('Failed to load protocol config:', e);
      this.renderProtocolConfigDefault();
    }
  },

  renderProtocolConfigDefault() {
    // Render with default values when API fails
    document.getElementById('protocol-config').innerHTML = `
      <div class="bg-gray-800 rounded p-3 text-center">
        <div class="text-gray-500 text-sm">Loading protocol configuration...</div>
        <div class="text-xs text-gray-400 mt-1">If this persists, check console for errors</div>
      </div>
    `;
  },

  renderProtocolConfig() {
    if (!this.protocolConfig) {
      this.renderProtocolConfigDefault();
      return;
    }

    document.getElementById('protocol-config').innerHTML = `
      <div class="bg-gray-800 rounded p-3">
        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input type="checkbox" id="http2-enabled" ${this.protocolConfig.http2_enabled ? 'checked' : ''} class="accent-indigo-500">
          <span>HTTP/2 Support</span>
        </label>
        <p class="text-xs text-gray-500 mt-1">Enable HTTP/2 protocol support for better performance</p>
      </div>

      <div class="bg-gray-800 rounded p-3">
        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input type="checkbox" id="http3-enabled" ${this.protocolConfig.http3_enabled ? 'checked' : ''} class="accent-indigo-500">
          <span>HTTP/3 Support</span>
        </label>
        <p class="text-xs text-gray-500 mt-1">
          Enable HTTP/3 over QUIC (requires restart)<br>
          <span class="text-yellow-400">⚠️ Disabled by default - HTTP/1.1 & HTTP/2 cover most testing needs</span>
        </p>
        <div class="text-xs text-gray-400 mt-2">
          <strong>Enable HTTP/3 when:</strong> Testing QUIC-specific applications, performance testing, or modern web apps requiring HTTP/3
        </div>
      </div>

      <div class="bg-gray-800 rounded p-3">
        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input type="checkbox" id="websocket-compression" ${this.protocolConfig.websocket_compression ? 'checked' : ''} class="accent-indigo-500">
          <span>WebSocket Compression</span>
        </label>
        <p class="text-xs text-gray-500 mt-1">Enable per-message deflate compression</p>
      </div>

      <div class="bg-gray-800 rounded p-3">
        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input type="checkbox" id="grpc-reflection" ${this.protocolConfig.grpc_reflection ? 'checked' : ''} class="accent-indigo-500">
          <span>gRPC Reflection</span>
        </label>
        <p class="text-xs text-gray-500 mt-1">Enable gRPC server reflection support</p>
      </div>

      <div class="bg-gray-800 rounded p-3">
        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
          <input type="checkbox" id="graphql-introspection" ${this.protocolConfig.graphql_introspection ? 'checked' : ''} class="accent-indigo-500">
          <span>GraphQL Introspection</span>
        </label>
        <p class="text-xs text-gray-500 mt-1">Enable GraphQL schema introspection</p>
      </div>
    `;
  },

  async saveProtocolConfig() {
    const config = {
      http2_enabled: document.getElementById('http2-enabled').checked,
      http3_enabled: document.getElementById('http3-enabled').checked,
      websocket_compression: document.getElementById('websocket-compression').checked,
      grpc_reflection: document.getElementById('grpc-reflection').checked,
      graphql_introspection: document.getElementById('graphql-introspection').checked
    };

    try {
      const resp = await authFetch('/api/proxy/protocols', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });

      if (!resp.ok) { Toast.show('Failed to save protocol config', 'error'); return; }
      const result = await resp.json();
      Toast.show('Protocol configuration saved', 'success');

      if (result.restart_required) {
        Toast.show('Proxy restart required for HTTP/3 changes', 'info', 5000);
      }
    } catch (e) {
      Toast.show('Failed to save protocol config', 'error');
    }
  },

  // ── SSL/TLS Management ─────────────────────────────────────────────

  async loadSSLInfo() {
    try {
      const [certsResp, infoResp] = await Promise.all([
        authFetch('/api/proxy/certificates'),
        authFetch('/api/proxy/ssl/info')
      ]);

      if (certsResp.ok && infoResp.ok) {
        const certificates = await certsResp.json();
        this.sslInfo = await infoResp.json();
        this.renderSSLInfo(certificates);
      } else {
        this.renderSSLInfoDefault();
      }
    } catch (e) {
      console.error('Failed to load SSL info:', e);
      this.renderSSLInfoDefault();
    }
  },

  renderSSLInfoDefault() {
    const sslInfoElement = document.getElementById('ssl-info');
    if (!sslInfoElement) {
      console.error('ssl-info element not found in renderSSLInfoDefault');
      return;
    }

    console.log('Rendering SSL info default/error state');
    sslInfoElement.innerHTML = `
      <div class="bg-gray-800 rounded p-3">
        <div class="text-red-400 text-sm">⚠️ SSL/TLS information unavailable</div>
        <div class="text-xs text-gray-400 mt-1">Check console for errors or try refreshing</div>
        <button onclick="AdvancedTab.loadSSLInfo()" class="mt-2 text-xs bg-blue-600 hover:bg-blue-500 text-white px-2 py-1 rounded">
          Retry Loading
        </button>
      </div>
    `;
  },

  renderSSLInfo(certificates) {
    const sslInfoElement = document.getElementById('ssl-info');
    if (!sslInfoElement) {
      console.error('ssl-info element not found');
      return;
    }

    console.log('Rendering SSL info with certificates:', certificates);
    sslInfoElement.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="space-y-2">
          <h4 class="text-xs font-semibold text-gray-300">Certificates</h4>
          ${certificates.certificates.map(cert => `
            <div class="bg-gray-800 rounded p-2 text-xs">
              <div class="font-mono text-green-400">${esc(cert.format)}</div>
              <div class="text-gray-400">Subject: ${esc(cert.subject)}</div>
              <div class="text-gray-500">Fingerprint: ${esc(cert.fingerprint.substring(0, 32))}...</div>
              <div class="text-gray-500">Valid: ${new Date(cert.not_before).toLocaleDateString()} - ${new Date(cert.not_after).toLocaleDateString()}</div>
            </div>
          `).join('')}
        </div>

        <div class="space-y-2">
          <h4 class="text-xs font-semibold text-gray-300">TLS Configuration</h4>
          <div class="bg-gray-800 rounded p-2 text-xs">
            <div>Versions: ${this.sslInfo.tls_versions.join(', ')}</div>
            <div>Certificate Validation: ${this.sslInfo.certificate_validation.enabled ? 'Enabled' : 'Disabled'}</div>
            <div>SNI Support: ${this.sslInfo.features.sni_support ? 'Yes' : 'No'}</div>
          </div>
        </div>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        ${['ios', 'android'].map(platform => `
          <button onclick="AdvancedTab.showSSLBypassProfile('${platform}')"
                  class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-2 rounded flex items-center gap-1">
            📱 ${platform.charAt(0).toUpperCase() + platform.slice(1)} Bypass
          </button>
        `).join('')}
      </div>
    `;
  },

  async downloadCertificate(format) {
    try {
      const resp = await authFetch(`/api/proxy/certificates/${format}`);
      if (!resp.ok) { Toast.show(`Failed to download ${format} certificate`, 'error'); return; }
      const data = await resp.json();

      const blob = new Blob([data.content], { type: data.mime_type });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = data.filename;
      a.click();

      URL.revokeObjectURL(url);
      Toast.show(`Certificate downloaded: ${data.filename}`, 'success');
    } catch (e) {
      Toast.show(`Failed to download ${format} certificate`, 'error');
    }
  },

  async regenerateCertificates() {
    if (!confirm('Regenerate CA certificates? This will invalidate existing certificates.')) return;

    try {
      await authFetch('/api/proxy/certificates/regenerate', { method: 'POST' });
      Toast.show('Certificates regenerated successfully', 'success');
      Toast.show('Proxy restart recommended', 'info', 5000);

      // Reload SSL info
      await this.loadSSLInfo();
    } catch (e) {
      Toast.show('Failed to regenerate certificates', 'error');
    }
  },

  async showSSLBypassProfile(platform) {
    try {
      const resp = await authFetch(`/api/proxy/ssl/bypass-profiles/install?profile_name=${platform}`);
      if (!resp.ok) { Toast.show('Failed to load SSL bypass profile', 'error'); return; }
      const data = await resp.json();

      const steps = data.installation.steps.map((step, i) =>
        `<div class="flex gap-2"><span class="text-indigo-400 font-mono">${i + 1}.</span><span>${esc(step)}</span></div>`
      ).join('');

      const script = data.installation.script;

      Toast.show(`
        <div class="text-left">
          <h4 class="font-semibold mb-2">${platform.charAt(0).toUpperCase() + platform.slice(1)} SSL Bypass Installation</h4>
          <div class="space-y-1 mb-3">${steps}</div>
          ${script ? `<details><summary class="cursor-pointer text-xs text-gray-400">Frida Script</summary><pre class="text-xs mt-1 p-2 bg-gray-800 rounded overflow-x-auto">${esc(script)}</pre></details>` : ''}
        </div>
      `, 'info', 15000);
    } catch (e) {
      Toast.show('Failed to load SSL bypass profile', 'error');
    }
  },

  // ── WebSocket Management ───────────────────────────────────────────

  async loadWebSocketConfig() {
    try {
      const resp = await authFetch('/api/proxy/websockets/config');
      if (!resp.ok) { Toast.show('Failed to load WebSocket config', 'error'); return; }
      this.websocketConfig = await resp.json();
      this.renderWebSocketConfig();
    } catch (e) {
      console.error('Failed to load WebSocket config:', e);
    }
  },

  renderWebSocketConfig() {
    if (!this.websocketConfig) return;

    document.getElementById('websocket-config').innerHTML = `
      <label class="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
        <input type="checkbox" id="ws-auto-ping" ${this.websocketConfig.auto_ping ? 'checked' : ''} class="accent-indigo-500">
        Auto Ping
      </label>

      <div class="flex items-center gap-2">
        <label class="text-xs text-gray-300">Ping Interval:</label>
        <input type="number" id="ws-ping-interval" value="${this.websocketConfig.ping_interval}"
               class="w-16 ${this._input}" min="5" max="300">
        <span class="text-xs text-gray-500">seconds</span>
      </div>

      <label class="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
        <input type="checkbox" id="ws-compression" ${this.websocketConfig.compression ? 'checked' : ''} class="accent-indigo-500">
        Compression
      </label>

      <div class="flex items-center gap-2">
        <label class="text-xs text-gray-300">History Limit:</label>
        <input type="number" id="ws-history-limit" value="${this.websocketConfig.message_history_limit}"
               class="w-20 ${this._input}" min="100" max="10000">
      </div>
    `;
  },

  async saveWebSocketConfig() {
    const config = {
      auto_ping: document.getElementById('ws-auto-ping').checked,
      ping_interval: parseInt(document.getElementById('ws-ping-interval').value),
      compression: document.getElementById('ws-compression').checked,
      message_history_limit: parseInt(document.getElementById('ws-history-limit').value)
    };

    try {
      await authFetch('/api/proxy/websockets/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });

      Toast.show('WebSocket configuration saved', 'success');
    } catch (e) {
      Toast.show('Failed to save WebSocket config', 'error');
    }
  },

  async refreshWebSockets() {
    try {
      const resp = await authFetch('/api/proxy/websockets/active');
      if (!resp.ok) { Toast.show('Failed to load active WebSockets', 'error'); return; }
      this.activeWebSockets = (await resp.json()).active_connections;
      this.renderActiveWebSockets();
    } catch (e) {
      console.error('Failed to load active WebSockets:', e);
    }
  },

  renderActiveWebSockets() {
    const container = document.getElementById('active-websockets');

    if (this.activeWebSockets.length === 0) {
      container.innerHTML = '<div class="text-gray-500 text-xs">No active WebSocket connections</div>';
      return;
    }

    container.innerHTML = this.activeWebSockets.map(ws => `
      <div class="bg-gray-800 rounded p-2 text-xs">
        <div class="flex items-center justify-between">
          <div class="font-mono text-green-400">${esc(ws.host)}</div>
          <button onclick="AdvancedTab.injectWebSocketMessage('${esc(ws.id)}')"
                  class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-1 py-0.5 rounded">
            💬 Inject
          </button>
        </div>
        <div class="text-gray-400">Messages: ${ws.message_count}</div>
        <div class="text-gray-500">Last: ${new Date(ws.last_activity * 1000).toLocaleTimeString()}</div>
      </div>
    `).join('');
  },

  async injectWebSocketMessage(wsId) {
    const message = prompt('Message to inject:');
    if (!message) return;

    const toClient = confirm('Send to client? (Cancel = send to server)');

    try {
      await authFetch(`/api/proxy/websockets/${wsId}/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, to_client: toClient })
      });

      Toast.show('Message injected into WebSocket', 'success');
    } catch (e) {
      Toast.show('Failed to inject message', 'error');
    }
  },

  // ── Protocol Analysis ──────────────────────────────────────────────

  async loadProtocolAnalysis() {
    try {
      const [graphqlResp, grpcResp] = await Promise.all([
        authFetch('/api/proxy/protocols/graphql/schemas'),
        authFetch('/api/proxy/protocols/grpc/services')
      ]);

      if (!graphqlResp.ok || !grpcResp.ok) { Toast.show('Failed to load protocol analysis', 'error'); return; }
      const graphqlData = await graphqlResp.json();
      const grpcData = await grpcResp.json();

      this.renderProtocolAnalysis(graphqlData, grpcData);
    } catch (e) {
      console.error('Failed to load protocol analysis:', e);
    }
  },

  renderProtocolAnalysis(graphqlData, grpcData) {
    // Render GraphQL schemas
    const graphqlContainer = document.getElementById('graphql-schemas');
    if (graphqlData.schemas.length > 0) {
      graphqlContainer.innerHTML = graphqlData.schemas.map(schema => `
        <div class="mb-2 p-2 bg-gray-700 rounded">
          <div class="font-mono text-purple-400">${esc(schema.url)}</div>
          <div class="text-gray-400">Types: ${esc(schema.types_count)}</div>
          <div class="text-gray-500">Discovered: ${new Date(schema.discovered_at * 1000).toLocaleDateString()}</div>
        </div>
      `).join('');
    }

    // Render gRPC services
    const grpcContainer = document.getElementById('grpc-services');
    if (grpcData.services.length > 0) {
      grpcContainer.innerHTML = grpcData.services.map(service => `
        <div class="mb-2 p-2 bg-gray-700 rounded">
          <div class="font-mono text-green-400">${esc(service.service_name || service.host)}${esc(service.path)}</div>
          <div class="text-gray-400">${esc(service.method_name || service.method)}</div>
          <div class="text-gray-500">Content-Type: ${esc(service.content_type)}</div>
        </div>
      `).join('');
    }
  },

  async detectProtocols() {
    try {
      const resp = await authFetch('/api/proxy/protocols/detect', {
        method: 'POST'
      });
      const data = await resp.json();

      Toast.show(`
        <div class="text-left">
          <h4 class="font-semibold mb-2">Protocol Detection Results</h4>
          <div class="space-y-1">
            ${Object.entries(data.protocols).map(([proto, count]) =>
              count > 0 ? `<div>${proto.toUpperCase()}: ${count} flows</div>` : ''
            ).filter(x => x).join('')}
          </div>
          ${data.recommendations.length > 0 ? `
            <div class="mt-2">
              <strong>Recommendations:</strong>
              <ul class="list-disc list-inside text-xs">
                ${data.recommendations.map(rec => `<li>${esc(rec)}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
      `, 'info', 8000);

      // Refresh protocol analysis
      await this.loadProtocolAnalysis();
    } catch (e) {
      Toast.show('Failed to detect protocols', 'error');
    }
  },

  showProtocolStats() {
    // This would show detailed protocol statistics
    Toast.show('Protocol statistics feature coming soon!', 'info');
  },

  // ── Advanced Modifications ─────────────────────────────────────────

  async loadModifications() {
    try {
      const resp = await authFetch('/api/proxy/modifications');
      if (!resp.ok) { Toast.show('Failed to load modifications', 'error'); return; }
      this.modifications = (await resp.json()).modifications;
      this.renderModifications();
    } catch (e) {
      console.error('Failed to load modifications:', e);
    }
  },

  renderModifications() {
    const container = document.getElementById('modifications-list');

    if (this.modifications.length === 0) {
      container.innerHTML = '<div class="text-gray-500 text-xs">No advanced modifications configured</div>';
      return;
    }

    container.innerHTML = this.modifications.map(mod => `
      <div class="bg-gray-800 rounded p-3 flex items-center justify-between">
        <div class="flex-1">
          <div class="flex items-center gap-2">
            <input type="checkbox" ${mod.enabled ? 'checked' : ''}
                   onchange="AdvancedTab.toggleModification('${esc(mod.id)}', this.checked)"
                   class="accent-indigo-500">
            <span class="text-sm text-white">${esc(mod.name)}</span>
          </div>
          <div class="text-xs text-gray-400 mt-1">${esc(mod.target_url_pattern)}</div>
        </div>
        <div class="flex gap-1">
          <button onclick="AdvancedTab.editModification('${esc(mod.id)}')"
                  class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-2 py-1 rounded">
            Edit
          </button>
          <button onclick="AdvancedTab.deleteModification('${esc(mod.id)}')"
                  class="text-xs bg-red-600 hover:bg-red-500 text-white px-2 py-1 rounded">
            Delete
          </button>
        </div>
      </div>
    `).join('');
  },

  async showModificationTemplates() {
    try {
      const resp = await authFetch('/api/proxy/modifications/templates');
      const data = await resp.json();

      document.getElementById('templates-content').innerHTML = `
        <div class="grid gap-4">
          ${data.templates.map(template => `
            <div class="bg-gray-800 rounded p-4">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <h4 class="text-white font-semibold">${esc(template.name)}</h4>
                  <p class="text-gray-400 text-sm mt-1">${esc(template.description)}</p>
                  <div class="text-xs text-gray-500 mt-2">Pattern: ${esc(template.target_url_pattern)}</div>
                </div>
                <button onclick="AdvancedTab.useTemplate(${JSON.stringify(template).replace(/"/g, '&quot;')})"
                        class="text-xs bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded">
                  Use Template
                </button>
              </div>
              ${template.script ? `
                <details class="mt-3">
                  <summary class="cursor-pointer text-xs text-gray-400">Script Preview</summary>
                  <pre class="text-xs mt-2 p-2 bg-gray-900 rounded overflow-x-auto">${esc(template.script)}</pre>
                </details>
              ` : ''}
            </div>
          `).join('')}
        </div>
      `;

      document.getElementById('templates-modal').classList.remove('hidden');
    } catch (e) {
      Toast.show('Failed to load templates', 'error');
    }
  },

  useTemplate(template) {
    document.getElementById('templates-modal').classList.add('hidden');
    this._selectedModification = {
      id: '',
      name: template.name,
      enabled: true,
      target_url_pattern: template.target_url_pattern,
      modifications: template.modifications,
      script: template.script
    };
    this.showModificationEditor();
  },

  createModification() {
    this._selectedModification = {
      id: '',
      name: 'New Modification',
      enabled: true,
      target_url_pattern: '*',
      modifications: {},
      script: ''
    };
    this.showModificationEditor();
  },

  editModification(modId) {
    this._selectedModification = this.modifications.find(m => m.id === modId);
    if (this._selectedModification) {
      this.showModificationEditor();
    }
  },

  showModificationEditor() {
    const mod = this._selectedModification;
    if (!mod) return;

    document.getElementById('editor-content').innerHTML = `
      <div class="space-y-4">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label class="block text-sm text-gray-300 mb-1">Name</label>
            <input type="text" id="mod-name" value="${esc(mod.name)}" class="w-full ${this._input}">
          </div>
          <div>
            <label class="block text-sm text-gray-300 mb-1">URL Pattern</label>
            <input type="text" id="mod-pattern" value="${esc(mod.target_url_pattern)}" class="w-full ${this._input}">
          </div>
        </div>

        <div>
          <label class="block text-sm text-gray-300 mb-1">Modifications (JSON)</label>
          <textarea id="mod-config" rows="6" class="w-full ${this._input} font-mono">${JSON.stringify(mod.modifications, null, 2)}</textarea>
        </div>

        <div>
          <label class="block text-sm text-gray-300 mb-1">Custom Script (JavaScript)</label>
          <textarea id="mod-script" rows="8" class="w-full ${this._input} font-mono" placeholder="// Custom modification script">${esc(mod.script || '')}</textarea>
        </div>

        <div class="flex justify-end gap-2">
          <button onclick="document.getElementById('editor-modal').classList.add('hidden')"
                  class="${this._btnSm}">Cancel</button>
          <button onclick="AdvancedTab.saveModification()"
                  class="${this._btn}">Save</button>
        </div>
      </div>
    `;

    document.getElementById('editor-modal').classList.remove('hidden');
  },

  async saveModification() {
    const modification = {
      id: this._selectedModification.id,
      name: document.getElementById('mod-name').value,
      enabled: true,
      target_url_pattern: document.getElementById('mod-pattern').value,
      modifications: JSON.parse(document.getElementById('mod-config').value || '{}'),
      script: document.getElementById('mod-script').value
    };

    try {
      await authFetch('/api/proxy/modifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(modification)
      });

      Toast.show('Modification saved', 'success');
      document.getElementById('editor-modal').classList.add('hidden');

      // Reload modifications
      await this.loadModifications();
    } catch (e) {
      Toast.show('Failed to save modification', 'error');
    }
  },

  async deleteModification(modId) {
    if (!confirm('Delete this modification?')) return;

    try {
      await authFetch(`/api/proxy/modifications/${modId}`, { method: 'DELETE' });
      Toast.show('Modification deleted', 'success');

      // Reload modifications
      await this.loadModifications();
    } catch (e) {
      Toast.show('Failed to delete modification', 'error');
    }
  },

  async toggleModification(modId, enabled) {
    // Update the modification's enabled state
    const mod = this.modifications.find(m => m.id === modId);
    if (mod) {
      mod.enabled = enabled;

      try {
        await authFetch('/api/proxy/modifications', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(mod)
        });

        Toast.show(`Modification ${enabled ? 'enabled' : 'disabled'}`, 'success');
      } catch (e) {
        Toast.show('Failed to update modification', 'error');
        // Revert checkbox state - would need to be handled differently
        console.warn('Failed to update modification state');
      }
    }
  }
};
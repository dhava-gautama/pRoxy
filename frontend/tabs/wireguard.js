// WireGuard VPN tab: VPN-based traffic capture for mobile devices and apps
window.WireGuardTab = {

  render() {
    return `
      <div class="max-w-4xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-white">🔒 WireGuard VPN Setup</h2>
          <div class="text-sm text-blue-400">✨ Captures ALL traffic - including apps that bypass proxy!</div>
        </div>

        <!-- Dual Mode Status -->
        <div class="bg-gray-900 rounded-lg p-6 border border-indigo-500">
          <h3 class="text-lg font-medium text-white mb-4">🚀 Dual Mode Operation</h3>
          <p class="text-gray-400 text-sm mb-4">
            pRoxy runs both <span class="text-green-400">regular proxy (HTTP/HTTPS)</span> and
            <span class="text-blue-400">WireGuard VPN</span> simultaneously for maximum coverage.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="bg-gray-800 p-4 rounded">
              <h4 class="text-green-400 font-medium mb-2">📡 Regular Proxy</h4>
              <div class="text-sm text-gray-300 space-y-1">
                <div>• Captures browser traffic</div>
                <div>• Port: <span class="font-mono text-blue-400">8080</span></div>
                <div>• Works with proxy-aware apps</div>
              </div>
            </div>
            <div class="bg-gray-800 p-4 rounded">
              <h4 class="text-blue-400 font-medium mb-2">🔒 WireGuard VPN</h4>
              <div class="text-sm text-gray-300 space-y-1">
                <div>• Captures ALL device traffic</div>
                <div>• Port: <span class="font-mono text-blue-400" id="wg-port">---</span></div>
                <div>• Works with any app</div>
              </div>
            </div>
          </div>
        </div>

        <!-- WireGuard Management -->
        <div class="bg-gray-900 rounded-lg p-6">
          <h3 class="text-lg font-medium text-white mb-4">🛠️ WireGuard Server Management</h3>

          <!-- WireGuard Status -->
          <div id="wg-status" class="bg-gray-800 p-4 rounded mb-6">
            <div class="flex items-center justify-between">
              <div>
                <h4 class="text-white font-medium">WireGuard VPN Status</h4>
                <div id="wg-status-text" class="text-sm text-gray-400">Loading...</div>
                <div id="wg-endpoint-text" class="text-xs text-gray-500 mt-1">Endpoint will be shown when running</div>
              </div>
              <div class="flex space-x-2">
                <button onclick="WireGuardTab.startWireGuard()"
                        id="start-wg-btn"
                        class="bg-green-600 hover:bg-green-500 text-white text-sm px-3 py-1.5 rounded">
                  Start VPN Server
                </button>
                <button onclick="WireGuardTab.stopWireGuard()"
                        id="stop-wg-btn"
                        class="bg-red-600 hover:bg-red-500 text-white text-sm px-3 py-1.5 rounded">
                  Stop VPN Server
                </button>
              </div>
            </div>
          </div>

          <!-- Client Management -->
          <div class="bg-gray-800 p-4 rounded">
            <h4 class="text-white font-medium mb-3">📱 Device Clients</h4>
            <p class="text-gray-400 text-sm mb-4">
              Create VPN profiles for your devices. Each device gets a unique config with QR code for easy setup.
            </p>

            <div class="flex justify-between items-center mb-4">
              <span class="text-sm text-gray-400">Add new device:</span>
              <button onclick="WireGuardTab.createWGClient()"
                      class="bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-1.5 rounded">
                ➕ Add Device
              </button>
            </div>

            <div id="wg-clients" class="space-y-2">
              <!-- Client list will be populated here -->
            </div>
          </div>

          <!-- Setup Instructions -->
          <div class="bg-gray-800 p-4 rounded mt-6">
            <h4 class="text-white font-medium mb-3">📖 Device Setup Instructions</h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h5 class="text-green-400 font-medium mb-2">📱 Android</h5>
                <ol class="text-gray-300 space-y-1 text-xs">
                  <li>1. Install WireGuard app from Play Store</li>
                  <li>2. Tap "+" → "Scan from QR code"</li>
                  <li>3. Scan the QR code generated above</li>
                  <li>4. Tap the toggle to connect</li>
                  <li>5. Check Traffic tab for captured data</li>
                </ol>
              </div>
              <div>
                <h5 class="text-blue-400 font-medium mb-2">🍎 iOS</h5>
                <ol class="text-gray-300 space-y-1 text-xs">
                  <li>1. Install WireGuard app from App Store</li>
                  <li>2. Tap "+" → "Create from QR code"</li>
                  <li>3. Scan the QR code generated above</li>
                  <li>4. Save the configuration</li>
                  <li>5. Toggle the VPN connection on</li>
                </ol>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  },

  async load() {
    await this.loadWireGuardStatus();
    await this.loadWireGuardClients();
  },

  // ── WireGuard Status Management ────────────────────────────

  async loadWireGuardStatus() {
    try {
      const resp = await authFetch('/api/wireguard/status');
      if (resp.ok) {
        const status = await resp.json();
        const statusText = document.getElementById('wg-status-text');
        const portText = document.getElementById('wg-port');
        const endpointText = document.getElementById('wg-endpoint-text');

        if (statusText) {
          statusText.innerHTML = status.running ?
            `<span class="text-green-400">✅ Running on port ${status.listen_port}</span>` :
            `<span class="text-red-400">⚠️ Not running</span>`;
        }

        if (portText) {
          portText.textContent = status.running ? status.listen_port : '---';
        }

        if (endpointText && status.running) {
          const hostname = window.location.hostname;
          endpointText.innerHTML = `<span class="text-blue-400">Endpoint: ${hostname}:${status.listen_port}</span>`;
        }
      }
    } catch (e) {
      console.error('Failed to load WireGuard status:', e);
    }
  },

  async loadWireGuardClients() {
    try {
      const resp = await authFetch('/api/wireguard/clients');
      if (resp.ok) {
        const clients = await resp.json();
        const container = document.getElementById('wg-clients');
        if (container) {
          if (clients.length === 0) {
            container.innerHTML = `
              <div class="text-center text-gray-500 py-6">
                <div class="text-3xl mb-2">📱</div>
                <div class="text-sm">No devices configured yet</div>
                <div class="text-xs text-gray-600 mt-1">Add your first device to get started</div>
              </div>`;
          } else {
            container.innerHTML = clients.map(client => `
              <div class="bg-gray-700 p-3 rounded-lg flex items-center justify-between">
                <div class="flex items-center space-x-3">
                  <div class="text-2xl">${this.getDeviceIcon(client.name)}</div>
                  <div>
                    <div class="text-white font-medium">${esc(client.name)}</div>
                    <div class="text-xs text-gray-400">
                      IP: ${esc(client.ip_address)} |
                      Added: ${new Date(client.created_at * 1000).toLocaleDateString()}
                      ${client.last_seen ? `| Last seen: ${new Date(client.last_seen * 1000).toLocaleString()}` : ''}
                    </div>
                  </div>
                </div>
                <div class="flex space-x-2">
                  <button onclick="WireGuardTab.showClientConfig('${esc(client.id)}')"
                          class="bg-blue-600 hover:bg-blue-500 text-white text-xs px-2 py-1 rounded">
                    📱 Show QR
                  </button>
                  <button onclick="WireGuardTab.downloadClientConfig('${esc(client.id)}')"
                          class="bg-green-600 hover:bg-green-500 text-white text-xs px-2 py-1 rounded">
                    📁 Download
                  </button>
                  <button onclick="WireGuardTab.deleteWGClient('${esc(client.id)}')"
                          class="bg-red-600 hover:bg-red-500 text-white text-xs px-2 py-1 rounded">
                    🗑️
                  </button>
                </div>
              </div>
            `).join('');
          }
        }
      }
    } catch (e) {
      console.error('Failed to load WireGuard clients:', e);
    }
  },

  getDeviceIcon(name) {
    const nameLower = name.toLowerCase();
    if (nameLower.includes('iphone') || nameLower.includes('ios')) return '📱';
    if (nameLower.includes('android')) return '🤖';
    if (nameLower.includes('ipad')) return '📲';
    if (nameLower.includes('laptop') || nameLower.includes('pc')) return '💻';
    if (nameLower.includes('mac')) return '🖥️';
    return '📱'; // default
  },

  // ── WireGuard Control Actions ──────────────────────────────

  async startWireGuard() {
    try {
      const resp = await authFetch('/api/wireguard/start', { method: 'POST' });
      if (resp.ok) {
        Toast.show('WireGuard VPN started successfully', 'success');
        await this.loadWireGuardStatus();
      } else {
        const error = await resp.text();
        Toast.show(`Failed to start WireGuard: ${error}`, 'error');
      }
    } catch (e) {
      Toast.show('Failed to start WireGuard VPN', 'error');
    }
  },

  async stopWireGuard() {
    try {
      const resp = await authFetch('/api/wireguard/stop', { method: 'POST' });
      if (resp.ok) {
        Toast.show('WireGuard VPN stopped successfully', 'success');
        await this.loadWireGuardStatus();
      } else {
        const error = await resp.text();
        Toast.show(`Failed to stop WireGuard: ${error}`, 'error');
      }
    } catch (e) {
      Toast.show('Failed to stop WireGuard VPN', 'error');
    }
  },

  async createWGClient() {
    const name = prompt('Enter device name (e.g., "iPhone 13", "Samsung Galaxy", "iPad"):');
    if (!name) return;

    try {
      const resp = await authFetch('/api/wireguard/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, device_type: 'mobile' })
      });

      if (resp.ok) {
        Toast.show('Device profile created successfully', 'success');
        await this.loadWireGuardClients();
      } else {
        const error = await resp.text();
        Toast.show(`Failed to create device profile: ${error}`, 'error');
      }
    } catch (e) {
      Toast.show('Failed to create WireGuard device profile', 'error');
    }
  },

  async deleteWGClient(clientId) {
    if (!confirm('Delete this device profile? The device will lose VPN access.')) return;

    try {
      const resp = await authFetch(`/api/wireguard/clients/${clientId}`, { method: 'DELETE' });
      if (resp.ok) {
        Toast.show('Device profile deleted', 'success');
        await this.loadWireGuardClients();
      } else {
        const error = await resp.text();
        Toast.show(`Failed to delete device: ${error}`, 'error');
      }
    } catch (e) {
      Toast.show('Failed to delete WireGuard device', 'error');
    }
  },

  async showClientConfig(clientId) {
    try {
      const resp = await authFetch(`/api/wireguard/clients/${clientId}/config?format=qr`);
      if (resp.ok) {
        const config = await resp.json();

        // Create modal with QR code
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/50';
        const isValidQR = config.qr_code && config.qr_code.startsWith('data:image');
        modal.innerHTML = `
          <div class="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-md">
            <h3 class="text-white font-bold mb-4">📱 ${esc(config.client_name) || 'Device'} Configuration</h3>

            ${isValidQR ? `
              <div class="bg-white p-4 rounded text-center mb-4">
                <img src="${config.qr_code}" alt="QR Code" class="mx-auto max-w-full" />
                <div class="text-xs text-gray-600 mt-2">Scan with WireGuard app</div>
              </div>
            ` : `
              <div class="bg-gray-800 p-4 rounded text-center mb-4">
                <div class="text-4xl mb-2">📱</div>
                <div class="text-xs text-gray-400">QR code requires <code>pip install qrcode[pil]</code></div>
                <div class="text-xs text-gray-500 mt-1">Download the config file instead</div>
              </div>
            `}

            <div class="text-xs text-gray-400 bg-gray-800 p-3 rounded mb-4">
              <div><strong>Device:</strong> ${esc(config.client_name) || 'Unknown'}</div>
              <div><strong>IP:</strong> ${esc(config.client_ip) || 'Unknown'}</div>
              <div><strong>Server:</strong> ${esc(config.server_endpoint) || 'Unknown'}</div>
            </div>

            <div class="flex space-x-2">
              <button onclick="WireGuardTab.downloadClientConfig('${esc(clientId)}')"
                      class="flex-1 bg-blue-600 hover:bg-blue-500 text-white text-sm px-3 py-2 rounded">
                📁 Download Config
              </button>
              <button onclick="this.parentElement.parentElement.parentElement.remove()"
                      class="bg-gray-600 hover:bg-gray-500 text-white text-sm px-3 py-2 rounded">
                Close
              </button>
            </div>
          </div>
        `;

        document.body.appendChild(modal);
        modal.addEventListener('click', (e) => {
          if (e.target === modal) modal.remove();
        });
      }
    } catch (e) {
      Toast.show('Failed to load device configuration', 'error');
    }
  },

  async downloadClientConfig(clientId) {
    try {
      const resp = await authFetch(`/api/wireguard/clients/${clientId}/config?format=text`);
      if (resp.ok) {
        const config = await resp.json();

        // Create downloadable file
        const blob = new Blob([config.config_text], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${(config.client_name || 'wireguard_client').replace(/[^a-zA-Z0-9]/g, '_')}_wireguard.conf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        Toast.show('Configuration downloaded successfully', 'success');
      }
    } catch (e) {
      Toast.show('Failed to download configuration', 'error');
    }
  }
};
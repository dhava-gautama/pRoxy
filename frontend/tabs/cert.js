// Cert tab: CA certificate info, regeneration, download + install instructions
window.CertTab = {
  _certInfo: null,
  _loading: false,

  async loadCertInfo() {
    try {
      const res = await authFetch('/api/cert/info');
      if (res.ok) this._certInfo = await res.json();
      else this._certInfo = null;
    } catch { this._certInfo = null; }
  },

  async regenerateCert() {
    if (!confirm(
      'Regenerate CA Certificate?\n\n' +
      'This will delete the current CA and generate a new one.\n' +
      'All devices that installed the old certificate must reinstall the new one.\n\n' +
      'Continue?'
    )) return;

    this._loading = true;
    this._rerender();
    try {
      const res = await authFetch('/api/cert/regenerate', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        this._certInfo = data.cert;
        Toast.show('CA certificate regenerated successfully', 'success');
      } else {
        const err = await res.json().catch(() => ({}));
        Toast.show(err.detail || 'Failed to regenerate certificate', 'error');
      }
    } catch {
      Toast.show('Failed to regenerate certificate', 'error');
    }
    this._loading = false;
    this._rerender();
  },

  _rerender() {
    const container = document.getElementById('cert-info-card');
    if (container) container.innerHTML = this._renderInfoCard();
  },

  _renderInfoCard() {
    if (!this._certInfo) {
      return `<p class="text-gray-500 text-sm italic">Certificate info not available. Start the proxy first.</p>`;
    }
    const c = this._certInfo;
    const from = new Date(c.not_before).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const to = new Date(c.not_after).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    return `
      <div class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
        <span class="text-gray-500">SHA-256</span>
        <span class="text-gray-300 font-mono text-xs break-all">${esc(c.fingerprint)}</span>
        <span class="text-gray-500">Subject</span>
        <span class="text-gray-300 text-xs">${esc(c.subject)}</span>
        <span class="text-gray-500">Valid From</span>
        <span class="text-gray-300">${from}</span>
        <span class="text-gray-500">Valid Until</span>
        <span class="text-gray-300">${to}</span>
      </div>`;
  },

  render() {
    this.loadCertInfo().then(() => this._rerender());

    return `
      <div class="max-w-3xl mx-auto p-6 space-y-6 overflow-y-auto" style="height:calc(100vh - 56px)">
        <h2 class="text-lg font-bold text-white">CA Certificate</h2>
        <p class="text-gray-400 text-sm">
          To intercept HTTPS traffic, install the mitmproxy CA certificate on your device.
          The certificate is auto-generated when the proxy first starts.
        </p>

        <div class="bg-gray-900 rounded-lg p-4 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-indigo-400">Certificate Info</h3>
            <button onclick="CertTab.regenerateCert()"
              class="bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded"
              ${this._loading ? 'disabled' : ''}>
              ${this._loading ? 'Regenerating...' : 'Regenerate Certificate'}
            </button>
          </div>
          <div id="cert-info-card">
            <p class="text-gray-500 text-sm italic">Loading...</p>
          </div>
        </div>

        <div class="flex gap-3 flex-wrap">
          <a href="/ca.pem" download class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-5 py-2.5 rounded inline-block">
            Download .pem
          </a>
          <a href="/ca.crt" download class="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-5 py-2.5 rounded inline-block">
            Download .crt
          </a>
          <a href="/ca.android" download class="bg-green-700 hover:bg-green-600 text-white text-sm px-5 py-2.5 rounded inline-block">
            Download .0 (Android System)
          </a>
        </div>

        <div class="space-y-4">
          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-indigo-400 mb-2">Linux</h3>
            <pre class="text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto">sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates</pre>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-indigo-400 mb-2">macOS</h3>
            <pre class="text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto">sudo security add-trusted-cert -d -r trustRoot \\
  -k /Library/Keychains/System.keychain mitmproxy-ca-cert.pem</pre>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-indigo-400 mb-2">Windows</h3>
            <pre class="text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto">certutil -addstore root mitmproxy-ca-cert.crt</pre>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-indigo-400 mb-2">Firefox</h3>
            <p class="text-xs text-gray-400">
              Settings &rarr; Privacy &amp; Security &rarr; Certificates &rarr; View Certificates &rarr; Import &rarr; Select the .crt file &rarr; Check "Trust this CA to identify websites"
            </p>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-green-400 mb-2">Android (User CA — no root)</h3>
            <p class="text-xs text-gray-400">
              Download the .crt file, then:<br>
              Settings &rarr; Security &rarr; Encryption &amp; credentials &rarr; Install a certificate &rarr; CA certificate &rarr; Select the file
            </p>
            <p class="text-xs text-yellow-400 mt-2">
              Note: User CAs only work for apps that trust them (most browsers). Many apps ignore user CAs on Android 7+.
            </p>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-green-400 mb-2">Android (System CA — requires root)</h3>
            <p class="text-xs text-gray-400 mb-2">
              Download the <code class="text-green-300">.0</code> file (hash-named), then push it as a system CA.
              This makes all apps trust the cert, bypassing Android 7+ restrictions.
            </p>
            <pre class="text-xs text-gray-300 bg-gray-800 rounded p-3 overflow-x-auto"># Download the .0 cert from the Cert tab
# Then push to device:
adb root
adb remount
adb push &lt;hash&gt;.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/&lt;hash&gt;.0
adb reboot</pre>
            <p class="text-xs text-gray-500 mt-2">
              For Magisk rooted devices, use the MagiskTrustUserCerts module instead.
            </p>
          </div>

          <div class="bg-gray-900 rounded-lg p-4">
            <h3 class="text-sm font-bold text-indigo-400 mb-2">iOS</h3>
            <p class="text-xs text-gray-400">
              1. Download the .pem file via Safari<br>
              2. Settings &rarr; General &rarr; VPN &amp; Device Management &rarr; Install profile<br>
              3. Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings &rarr; Enable full trust
            </p>
          </div>
        </div>
      </div>`;
  }
};

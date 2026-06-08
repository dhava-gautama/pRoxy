// Analytics tab: advanced traffic analysis, metrics dashboard, security insights
window.AnalyticsTab = {
  metrics: null,
  timeline: null,
  contentAnalysis: null,
  secrets: null,
  threatDetection: null,
  threatStats: null,
  refreshInterval: null,
  autoRefresh: false,
  currentView: 'overview', // overview, timeline, content, security, export

  render() {
    return `
      <div class="max-w-7xl mx-auto p-6 space-y-6" style="height:calc(100vh - 56px); overflow-y: auto;">
        <!-- Header -->
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-bold text-white">Traffic Analytics</h2>
          <div class="flex items-center gap-3">
            <label class="flex items-center gap-1 text-xs text-gray-400">
              <input type="checkbox" onchange="AnalyticsTab.toggleAutoRefresh(this.checked)" class="accent-indigo-500"> Auto-refresh
            </label>
            <button onclick="AnalyticsTab.refreshData()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded">
              Refresh Data
            </button>
          </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="flex space-x-1 bg-gray-900 rounded-lg p-1">
          <button onclick="AnalyticsTab.setView('overview')"
            class="analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors"
            data-view="overview">Overview</button>
          <button onclick="AnalyticsTab.setView('timeline')"
            class="analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors"
            data-view="timeline">Timeline</button>
          <button onclick="AnalyticsTab.setView('content')"
            class="analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors"
            data-view="content">Content Analysis</button>
          <button onclick="AnalyticsTab.setView('security')"
            class="analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors"
            data-view="security">Security</button>
          <button onclick="AnalyticsTab.setView('export')"
            class="analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors"
            data-view="export">Export</button>
        </div>

        <!-- Content Views -->
        <div id="analytics-content">
          <div class="text-center text-gray-500 py-8">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500 mx-auto mb-2"></div>
            Loading analytics data...
          </div>
        </div>
      </div>`;
  },

  // ── Data Management ────────────────────────────────────────

  async load() {
    await this.refreshData();
    this.setView('overview');
  },

  async refreshData() {
    try {
      // Load all analytics data in parallel
      const [metricsResp, timelineResp, contentResp, secretsResp, threatResp, threatStatsResp] = await Promise.all([
        authFetch('/api/analytics/metrics?limit=1000&time_range=3600'),
        authFetch('/api/analytics/timeline?limit=500&interval_minutes=5'),
        authFetch('/api/analytics/content/analysis?limit=1000'),
        authFetch('/api/analytics/content/secrets?limit=1000'),
        authFetch('/api/threat-detection/scan?limit=1000&time_range=3600&min_severity=low'),
        authFetch('/api/threat-detection/statistics?limit=1000&time_range=86400')
      ]);

      if (![metricsResp, timelineResp, contentResp, secretsResp, threatResp, threatStatsResp].every(r => r.ok)) {
        Toast.show('Failed to load analytics data', 'error');
        return;
      }
      this.metrics = await metricsResp.json();
      this.timeline = await timelineResp.json();
      this.contentAnalysis = await contentResp.json();
      this.secrets = await secretsResp.json();
      this.threatDetection = await threatResp.json();
      this.threatStats = await threatStatsResp.json();

      // Refresh current view
      this.setView(this.currentView);

    } catch (error) {
      console.error('Failed to load analytics data:', error);
      Toast.show('Failed to load analytics data', 'error');
    }
  },

  toggleAutoRefresh(enabled) {
    this.autoRefresh = enabled;
    if (enabled) {
      this.refreshInterval = setInterval(() => this.refreshData(), 30000); // 30 seconds
    } else if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  },

  // ── View Management ─────────────────────────────────────────

  setView(view) {
    this.currentView = view;

    // Update tab styling
    document.querySelectorAll('.analytics-tab').forEach(tab => {
      if (tab.dataset.view === view) {
        tab.className = 'analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors bg-indigo-600 text-white';
      } else {
        tab.className = 'analytics-tab px-3 py-1.5 text-xs font-medium rounded transition-colors text-gray-400 hover:text-white hover:bg-gray-800';
      }
    });

    // Render view content
    const content = document.getElementById('analytics-content');

    switch (view) {
      case 'overview':
        content.innerHTML = this.renderOverview();
        break;
      case 'timeline':
        content.innerHTML = this.renderTimeline();
        break;
      case 'content':
        content.innerHTML = this.renderContentAnalysis();
        break;
      case 'security':
        content.innerHTML = this.renderSecurityAnalysis();
        break;
      case 'export':
        content.innerHTML = this.renderExportTools();
        break;
    }
  },

  // ── Overview Dashboard ──────────────────────────────────────

  renderOverview() {
    if (!this.metrics) return '<div class="text-center text-gray-500">No data available</div>';

    const m = this.metrics;
    const errorRate = m.error_rate_percent;
    const errorRateColor = errorRate > 10 ? 'text-red-400' : errorRate > 5 ? 'text-yellow-400' : 'text-green-400';

    return `
      <!-- Key Metrics Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Total Requests</div>
          <div class="text-2xl font-bold text-white">${m.total_requests.toLocaleString()}</div>
          <div class="text-xs text-gray-500">${m.requests_per_minute.toFixed(1)} req/min</div>
        </div>
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Avg Response Time</div>
          <div class="text-2xl font-bold text-white">${m.avg_response_time_ms.toFixed(0)}ms</div>
          <div class="text-xs ${m.avg_response_time_ms > 1000 ? 'text-red-400' : 'text-green-400'}">
            ${m.avg_response_time_ms > 1000 ? 'Slow' : 'Good'}
          </div>
        </div>
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Error Rate</div>
          <div class="text-2xl font-bold ${errorRateColor}">${errorRate.toFixed(1)}%</div>
          <div class="text-xs text-gray-500">${Object.values(m.status_codes).reduce((a, b) => a + (b >= 400 ? b : 0), 0)} errors</div>
        </div>
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Data Transfer</div>
          <div class="text-2xl font-bold text-white">${this.formatBytes(m.total_response_size_bytes)}</div>
          <div class="text-xs text-gray-500">↑${this.formatBytes(m.total_request_size_bytes)}</div>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Status Codes -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">Status Code Distribution</h3>
          <div class="space-y-2">
            ${Object.entries(m.status_codes).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([code, count]) => {
              const percentage = (count / m.total_requests * 100);
              const color = code.startsWith('2') ? 'bg-green-500' :
                           code.startsWith('3') ? 'bg-blue-500' :
                           code.startsWith('4') ? 'bg-yellow-500' : 'bg-red-500';
              return `
                <div class="flex items-center justify-between text-xs">
                  <span class="text-gray-300">${code}</span>
                  <div class="flex items-center gap-2">
                    <div class="w-16 h-2 bg-gray-700 rounded-full">
                      <div class="${color} h-2 rounded-full" style="width: ${Math.max(2, percentage)}%"></div>
                    </div>
                    <span class="text-gray-400 w-8 text-right">${count}</span>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <!-- Top Hosts -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">Top Hosts</h3>
          <div class="space-y-2">
            ${Object.entries(m.top_hosts).slice(0, 8).map(([host, count]) => {
              const percentage = (count / m.total_requests * 100);
              return `
                <div class="flex items-center justify-between text-xs">
                  <span class="text-gray-300 truncate max-w-[120px]" title="${esc(host)}">${esc(host)}</span>
                  <div class="flex items-center gap-2">
                    <div class="w-16 h-2 bg-gray-700 rounded-full">
                      <div class="bg-indigo-500 h-2 rounded-full" style="width: ${Math.max(2, percentage)}%"></div>
                    </div>
                    <span class="text-gray-400 w-8 text-right">${count}</span>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>

      <!-- Security Highlights -->
      ${this.secrets && this.secrets.total_findings > 0 ? `
        <div class="bg-red-900/20 border border-red-800 rounded-lg p-4 mt-6">
          <div class="flex items-center gap-2 mb-2">
            <div class="w-2 h-2 bg-red-500 rounded-full"></div>
            <h3 class="text-sm font-medium text-red-400">Security Alert</h3>
          </div>
          <p class="text-sm text-gray-300">
            Found <strong>${this.secrets.total_findings}</strong> potential secrets in traffic.
            <a href="#" onclick="AnalyticsTab.setView('security')" class="text-red-400 hover:text-red-300 underline">
              Review security findings →
            </a>
          </p>
        </div>
      ` : ''}
    `;
  },

  // ── Timeline View ───────────────────────────────────────────

  renderTimeline() {
    if (!this.timeline) return '<div class="text-center text-gray-500">No timeline data available</div>';

    const maxRequests = Math.max(...this.timeline.timeline.map(t => t.requests));

    return `
      <div class="bg-gray-900 rounded-lg p-4">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-sm font-medium text-gray-400">Traffic Timeline (${this.timeline.interval_minutes} minute intervals)</h3>
          <div class="text-xs text-gray-500">${this.timeline.total_intervals} intervals</div>
        </div>

        <!-- Timeline Chart -->
        <div class="space-y-3">
          ${this.timeline.timeline.map(interval => {
            const width = (interval.requests / maxRequests * 100);
            const errorRate = interval.error_rate;
            const barColor = errorRate > 20 ? 'bg-red-500' : errorRate > 10 ? 'bg-yellow-500' : 'bg-indigo-500';

            return `
              <div class="flex items-center gap-3 text-xs">
                <div class="text-gray-400 w-16 text-right">${new Date(interval.datetime).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
                <div class="flex-1">
                  <div class="flex items-center gap-2">
                    <div class="w-full max-w-md h-6 bg-gray-800 rounded">
                      <div class="${barColor} h-6 rounded flex items-center justify-center text-white font-medium"
                           style="width: ${Math.max(1, width)}%">
                        ${interval.requests > 0 ? interval.requests : ''}
                      </div>
                    </div>
                    <div class="text-gray-400 w-20">${interval.requests} req</div>
                    ${interval.errors > 0 ? `<div class="text-red-400 w-16">${interval.errors} err</div>` : ''}
                    <div class="text-gray-500 w-16">${interval.avg_response_time_ms.toFixed(0)}ms</div>
                  </div>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  },

  // ── Content Analysis ────────────────────────────────────────

  renderContentAnalysis() {
    if (!this.contentAnalysis) return '<div class="text-center text-gray-500">No content analysis available</div>';

    const ca = this.contentAnalysis;

    return `
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- File Types -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">File Types</h3>
          <div class="space-y-2 max-h-48 overflow-y-auto">
            ${Object.entries(ca.file_types).slice(0, 15).map(([ext, count]) => `
              <div class="flex items-center justify-between text-xs">
                <span class="text-gray-300">.${esc(ext)}</span>
                <span class="text-gray-400">${count}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- API Endpoints -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">API Endpoints (${ca.api_endpoints.length})</h3>
          <div class="space-y-1 max-h-48 overflow-y-auto">
            ${ca.api_endpoints.slice(0, 20).map(endpoint => `
              <div class="text-xs text-gray-300 font-mono">${esc(endpoint)}</div>
            `).join('')}
          </div>
        </div>

        <!-- Authentication -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">Authentication Patterns</h3>
          <div class="space-y-2">
            ${Object.entries(ca.authentication_patterns).map(([type, count]) => `
              <div class="flex items-center justify-between text-xs">
                <span class="text-gray-300">${esc(type.replace('_', ' '))}</span>
                <span class="text-gray-400">${count}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Security Headers -->
        <div class="bg-gray-900 rounded-lg p-4">
          <h3 class="text-sm font-medium text-gray-400 mb-3">Security Headers</h3>
          <div class="space-y-2">
            ${Object.entries(ca.security_headers).map(([header, count]) => `
              <div class="flex items-center justify-between text-xs">
                <span class="text-gray-300">${esc(header)}</span>
                <span class="text-green-400">${count} responses</span>
              </div>
            `).join('')}
          </div>
          ${Object.keys(ca.security_headers).length === 0 ?
            '<div class="text-xs text-yellow-400">⚠ No security headers detected</div>' : ''}
        </div>
      </div>

      <!-- Sensitive Data Summary -->
      ${Object.keys(ca.sensitive_data || {}).length > 0 ? `
        <div class="bg-yellow-900/20 border border-yellow-800 rounded-lg p-4 mt-6">
          <h3 class="text-sm font-medium text-yellow-400 mb-2">Potentially Sensitive Data Detected</h3>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            ${Object.entries(ca.sensitive_data).map(([type, count]) => `
              <div class="text-gray-300">
                <span class="capitalize">${esc(type.replace('_', ' '))}</span>: <span class="text-yellow-400">${count}</span>
              </div>
            `).join('')}
          </div>
          <p class="text-xs text-gray-400 mt-2">Review these findings in the Security tab for details.</p>
        </div>
      ` : ''}
    `;
  },

  // ── Security Analysis ───────────────────────────────────────

  renderSecurityAnalysis() {
    if (!this.secrets && !this.threatDetection) return '<div class="text-center text-gray-500">No security analysis available</div>';

    const highConfidenceFindings = this.secrets?.findings.filter(f => f.confidence >= 0.8) || [];
    const criticalAlerts = this.threatDetection?.alerts.filter(a => a.severity === 'critical') || [];
    const highAlerts = this.threatDetection?.alerts.filter(a => a.severity === 'high') || [];

    return `
      <!-- Threat Detection Dashboard -->
      ${this.threatDetection ? `
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div class="bg-gray-900 rounded-lg p-4">
            <div class="text-sm text-gray-400">Active Threats</div>
            <div class="text-2xl font-bold text-red-400">${this.threatDetection.alerts.length}</div>
            <div class="text-xs text-gray-500">${this.threatDetection.scan_info.flows_analyzed} flows scanned</div>
          </div>
          <div class="bg-gray-900 rounded-lg p-4">
            <div class="text-sm text-gray-400">Critical Alerts</div>
            <div class="text-2xl font-bold text-red-500">${criticalAlerts.length}</div>
            <div class="text-xs text-gray-500">Immediate attention required</div>
          </div>
          <div class="bg-gray-900 rounded-lg p-4">
            <div class="text-sm text-gray-400">High Risk</div>
            <div class="text-2xl font-bold text-orange-400">${highAlerts.length}</div>
            <div class="text-xs text-gray-500">Potential security issues</div>
          </div>
          <div class="bg-gray-900 rounded-lg p-4">
            <div class="text-sm text-gray-400">Attack Categories</div>
            <div class="text-2xl font-bold text-yellow-400">${Object.keys(this.threatDetection.summary.by_category || {}).length}</div>
            <div class="text-xs text-gray-500">Different attack types</div>
          </div>
        </div>
      ` : ''}

      <!-- Critical Threat Alerts -->
      ${criticalAlerts.length > 0 ? `
        <div class="bg-red-900/30 border-2 border-red-600 rounded-lg p-4 mb-6">
          <h3 class="text-sm font-medium text-red-400 mb-3">🚨 CRITICAL SECURITY ALERTS</h3>
          <div class="space-y-3 max-h-64 overflow-y-auto">
            ${criticalAlerts.slice(0, 5).map(alert => `
              <div class="bg-red-900/20 rounded p-3 border-l-4 border-red-500">
                <div class="flex items-center justify-between mb-2">
                  <div class="text-sm">
                    <span class="text-red-300 font-medium">${esc(alert.title)}</span>
                    <span class="text-gray-400 ml-2">[${esc(alert.category.toUpperCase())}]</span>
                  </div>
                  <div class="text-xs text-red-400">
                    ${(alert.confidence * 100).toFixed(0)}% confidence
                  </div>
                </div>
                <p class="text-xs text-gray-300 mb-2">${esc(alert.description)}</p>
                <div class="text-xs text-gray-400">
                  Affected flows: ${alert.flow_ids.length}
                </div>
                ${alert.mitigation ? `
                  <div class="mt-2 text-xs text-yellow-200 bg-yellow-900/20 p-2 rounded">
                    <strong>Mitigation:</strong> ${esc(alert.mitigation)}
                  </div>
                ` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- Security Summary -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Total Findings</div>
          <div class="text-2xl font-bold text-red-400">${this.secrets.total_findings}</div>
          <div class="text-xs text-gray-500">${this.secrets.summary.unique_types} types</div>
        </div>
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">High Confidence</div>
          <div class="text-2xl font-bold text-yellow-400">${this.secrets.summary.high_confidence_count}</div>
          <div class="text-xs text-gray-500">Likely real secrets</div>
        </div>
        <div class="bg-gray-900 rounded-lg p-4">
          <div class="text-sm text-gray-400">Risk Level</div>
          <div class="text-2xl font-bold ${this.secrets.total_findings > 10 ? 'text-red-400' : this.secrets.total_findings > 0 ? 'text-yellow-400' : 'text-green-400'}">
            ${this.secrets.total_findings > 10 ? 'HIGH' : this.secrets.total_findings > 0 ? 'MEDIUM' : 'LOW'}
          </div>
        </div>
      </div>

      <!-- Secret Types Breakdown -->
      <div class="bg-gray-900 rounded-lg p-4 mb-6">
        <h3 class="text-sm font-medium text-gray-400 mb-3">Secret Types Found</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          ${Object.entries(this.secrets.summary.by_type).map(([type, count]) => `
            <div class="text-xs">
              <div class="text-gray-300 font-medium">${esc(type.replace('_', ' ').toUpperCase())}</div>
              <div class="text-gray-400">${count} occurrences</div>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- High-Confidence Findings -->
      ${highConfidenceFindings.length > 0 ? `
        <div class="bg-red-900/20 border border-red-800 rounded-lg p-4 mb-6">
          <h3 class="text-sm font-medium text-red-400 mb-3">🚨 High-Confidence Security Findings</h3>
          <div class="space-y-3 max-h-96 overflow-y-auto">
            ${highConfidenceFindings.slice(0, 10).map(finding => `
              <div class="bg-gray-900/50 rounded p-3 border-l-4 border-red-500">
                <div class="flex items-center justify-between mb-2">
                  <div class="text-xs">
                    <span class="text-red-400 font-medium">${esc(finding.secret_type.replace('_', ' ').toUpperCase())}</span>
                    <span class="text-gray-400 ml-2">in ${esc(finding.location)}</span>
                  </div>
                  <div class="text-xs text-gray-500">
                    Confidence: ${(finding.confidence * 100).toFixed(0)}%
                  </div>
                </div>
                <div class="text-xs text-gray-300 font-mono bg-gray-800 p-2 rounded">
                  ${esc(finding.context)}
                </div>
                <div class="text-xs text-gray-400 mt-1">
                  ${esc(finding.flow_method)} ${esc(finding.flow_url)}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- All Findings -->
      <div class="bg-gray-900 rounded-lg p-4">
        <h3 class="text-sm font-medium text-gray-400 mb-3">All Security Findings</h3>
        <div class="space-y-2 max-h-96 overflow-y-auto">
          ${this.secrets.findings.slice(0, 50).map(finding => {
            const confidenceColor = finding.confidence >= 0.8 ? 'text-red-400' :
                                    finding.confidence >= 0.6 ? 'text-yellow-400' : 'text-gray-400';
            return `
              <div class="flex items-start gap-3 text-xs p-2 hover:bg-gray-800 rounded">
                <div class="w-2 h-2 ${confidenceColor.replace('text-', 'bg-')} rounded-full mt-1.5"></div>
                <div class="flex-1">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="${confidenceColor} font-medium">${esc(finding.secret_type.replace('_', ' '))}</span>
                    <span class="text-gray-500">•</span>
                    <span class="text-gray-400">${esc(finding.location)}</span>
                    <span class="text-gray-500">•</span>
                    <span class="text-gray-500">${(finding.confidence * 100).toFixed(0)}%</span>
                  </div>
                  <div class="text-gray-400">${esc(finding.flow_method)} ${esc(finding.flow_url)}</div>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  },

  // ── Export Tools ────────────────────────────────────────────

  renderExportTools() {
    return `
      <div class="space-y-6">
        <!-- Export Options -->
        <div class="bg-gray-900 rounded-lg p-6">
          <h3 class="text-lg font-medium text-white mb-4">Export Analytics Report</h3>
          <div class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <button onclick="AnalyticsTab.exportSummary('json')"
                class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-3 rounded-lg text-sm font-medium">
                📄 Export JSON Report
              </button>
              <button onclick="AnalyticsTab.exportSummary('html')"
                class="bg-green-600 hover:bg-green-500 text-white px-4 py-3 rounded-lg text-sm font-medium">
                🌐 Export HTML Report
              </button>
            </div>
            <p class="text-xs text-gray-400">
              Export comprehensive traffic analysis including metrics, security findings, and recommendations.
            </p>
          </div>
        </div>

        <!-- Advanced Filters -->
        <div class="bg-gray-900 rounded-lg p-6">
          <h3 class="text-lg font-medium text-white mb-4">Advanced Traffic Filtering</h3>
          <div class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input type="text" id="filter-host" placeholder="Host pattern (regex)"
                class="bg-gray-800 text-gray-300 px-3 py-2 rounded border border-gray-700 text-sm">
              <input type="text" id="filter-path" placeholder="Path pattern (regex)"
                class="bg-gray-800 text-gray-300 px-3 py-2 rounded border border-gray-700 text-sm">
              <select id="filter-method" class="bg-gray-800 text-gray-300 px-3 py-2 rounded border border-gray-700 text-sm">
                <option value="">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input type="text" id="filter-status" placeholder="Status range (e.g. 400-499)"
                class="bg-gray-800 text-gray-300 px-3 py-2 rounded border border-gray-700 text-sm">
              <input type="text" id="filter-size" placeholder="Size range (bytes)"
                class="bg-gray-800 text-gray-300 px-3 py-2 rounded border border-gray-700 text-sm">
              <label class="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" id="filter-secrets" class="accent-indigo-500">
                Contains sensitive data
              </label>
            </div>
            <button onclick="AnalyticsTab.applyAdvancedFilter()"
              class="bg-yellow-600 hover:bg-yellow-500 text-white px-4 py-2 rounded text-sm font-medium">
              🔍 Apply Advanced Filter
            </button>
          </div>
        </div>

        <!-- Filter Results -->
        <div id="filter-results" class="hidden bg-gray-900 rounded-lg p-4">
          <h4 class="text-sm font-medium text-gray-400 mb-3">Filter Results</h4>
          <div id="filter-results-content"></div>
        </div>
      </div>
    `;
  },

  // ── Export Functions ────────────────────────────────────────

  async exportSummary(format) {
    try {
      const response = await authFetch(`/api/analytics/export/summary?format=${format}&limit=1000`);

      if (format === 'json') {
        const data = await response.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        this.downloadFile(blob, 'pRoxy_analytics_report.json');
      } else if (format === 'html') {
        const data = await response.json();
        const blob = new Blob([data.html], { type: 'text/html' });
        this.downloadFile(blob, 'pRoxy_analytics_report.html');
      }

      Toast.show(`${format.toUpperCase()} report exported successfully`, 'success');
    } catch (error) {
      Toast.show('Export failed: ' + error.message, 'error');
    }
  },

  async applyAdvancedFilter() {
    const params = new URLSearchParams();

    const host = document.getElementById('filter-host').value.trim();
    const path = document.getElementById('filter-path').value.trim();
    const method = document.getElementById('filter-method').value;
    const status = document.getElementById('filter-status').value.trim();
    const size = document.getElementById('filter-size').value.trim();
    const secrets = document.getElementById('filter-secrets').checked;

    if (host) params.append('host_pattern', host);
    if (path) params.append('path_pattern', path);
    if (method) params.append('method', method);
    if (status) params.append('status_code_range', status);
    if (size) params.append('response_size_range', size);
    if (secrets) params.append('has_sensitive_data', 'true');

    try {
      const response = await authFetch(`/api/analytics/filter/advanced?${params.toString()}&limit=100`);
      const data = await response.json();

      const resultsDiv = document.getElementById('filter-results');
      const contentDiv = document.getElementById('filter-results-content');

      contentDiv.innerHTML = `
        <div class="mb-3">
          <span class="text-sm text-gray-400">Found ${data.total_matches} matching flows</span>
        </div>
        <div class="space-y-2 max-h-96 overflow-y-auto">
          ${data.flows.map(flow => `
            <div class="flex items-center justify-between p-2 bg-gray-800 rounded text-xs">
              <div class="flex items-center gap-3">
                <span class="text-yellow-400 w-12">${esc(flow.method)}</span>
                <span class="text-indigo-400">${esc(flow.status_code)}</span>
                <span class="text-gray-300 truncate max-w-xs">${esc(flow.url)}</span>
              </div>
              <div class="flex items-center gap-2 text-gray-400">
                <span>${flow.duration_ms}ms</span>
                <span>${this.formatBytes(flow.response_size || 0)}</span>
              </div>
            </div>
          `).join('')}
        </div>
      `;

      resultsDiv.classList.remove('hidden');
      Toast.show(`Found ${data.total_matches} matching flows`, 'success');

    } catch (error) {
      Toast.show('Filter failed: ' + error.message, 'error');
    }
  },

  // ── Utility Functions ──────────────────────────────────────

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  },

  downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
};
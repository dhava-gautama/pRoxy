// Tab router + WebSocket client + keyboard shortcuts + theme
(function() {
  const content = document.getElementById('tab-content');
  const tabBar = document.getElementById('tab-bar');
  const wsStatus = document.getElementById('ws-status');
  let currentTab = 'traffic';
  let ws = null;

  // Initialize theme
  ThemeManager.init();

  function switchTab(tab) {
    if (currentTab === 'intercept') InterceptTab.stop();
    currentTab = tab;
    tabBar.querySelectorAll('button').forEach(btn => {
      btn.className = btn.dataset.tab === tab
        ? 'px-3 py-2 text-sm tab-active'
        : 'px-3 py-2 text-sm tab-inactive';
    });
    switch (tab) {
      case 'traffic':
        content.innerHTML = TrafficTab.render();
        TrafficTab._updateFiltered();
        TrafficTab.renderList();
        break;
      case 'replay':
        content.innerHTML = ReplayTab.render();
        ReplayTab.load();
        break;
      case 'rules':
        content.innerHTML = RulesTab.render();
        RulesTab.load();
        break;
      case 'dns':
        content.innerHTML = DNSTab.render();
        DNSTab.load();
        break;
      case 'intercept':
        content.innerHTML = InterceptTab.render();
        InterceptTab.start();
        break;
      case 'analytics':
        content.innerHTML = AnalyticsTab.render();
        AnalyticsTab.load();
        break;
      case 'cert':
        content.innerHTML = CertTab.render();
        break;
      case 'advanced':
        content.innerHTML = AdvancedTab.render();
        AdvancedTab.load();
        break;
      case 'wireguard':
        content.innerHTML = WireGuardTab.render();
        WireGuardTab.load();
        break;
      case 'offensive':
        content.innerHTML = OffensiveTab.render();
        break;
      case 'tools':
        content.innerHTML = ToolsTab.render();
        ToolsTab.loadSSLProfiles();
        ToolsTab.applyPrefill();
        break;
      case 'openapi':
        content.innerHTML = OpenAPITab.render();
        OpenAPITab.load();
        break;
      case 'issues':
        content.innerHTML = IssuesTab.render();
        IssuesTab.load();
        break;
      case 'authz':
        content.innerHTML = AuthzTab.render();
        AuthzTab.load();
        break;
      case 'import':
        content.innerHTML = ImporterTab.render();
        ImporterTab.load();
        break;
      case 'sessions':
        content.innerHTML = SessionsTab.render();
        SessionsTab.load();
        break;
      case 'scripts':
        content.innerHTML = ScriptsTab.render();
        ScriptsTab.load();
        break;
    }
  }

  window._switchTab = switchTab;
  window._getCurrentTab = () => currentTab;

  tabBar.addEventListener('click', e => {
    const tab = e.target.dataset?.tab;
    if (tab) switchTab(tab);
  });

  // WebSocket connection
  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const key = getAuthKey();
    const authParam = key ? `?key=${encodeURIComponent(key)}` : '';
    ws = new WebSocket(`${proto}//${location.host}/ws/traffic${authParam}`);

    ws.onopen = () => {
      wsStatus.className = 'w-2 h-2 rounded-full bg-green-500';
      wsStatus.title = 'Connected';
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        // Handle special message types
        if (data.type === 'flows_cleared') {
          // Another client cleared flows - update our local state
          console.log(`Flows cleared by another client: ${data.deleted} flows`);
          TrafficTab.flows = [];
          TrafficTab.flowMap = {};
          TrafficTab.selectedId = null;
          TrafficTab.compareId = null;
          TrafficTab._filteredFlows = [];
          TrafficTab.renderList();
          document.getElementById('flow-detail').innerHTML = FlowDetail.render(null);
          document.getElementById('flow-count').textContent = '0 flows';
          Toast.show(`${data.deleted} flows cleared (by another session)`, 'info');
        } else if (data.id) {
          // Regular flow update (flows have an 'id' field)
          TrafficTab.onFlowUpdate(data);
        } else {
          // Unknown message type, log and ignore
          console.debug('Unknown WebSocket message type:', data);
        }
      } catch (e) {
        console.warn('Failed to parse WebSocket message:', e);
      }
    };

    ws.onclose = () => {
      wsStatus.className = 'w-2 h-2 rounded-full bg-red-500';
      wsStatus.title = 'Disconnected';
      setTimeout(connectWS, 2000);
    };

    ws.onerror = () => ws.close();
  }

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    const isInput = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT';

    // Ctrl/Cmd shortcuts work everywhere
    if (e.ctrlKey || e.metaKey) {
      if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        if (currentTab === 'traffic') {
          const filterEl = document.getElementById('flow-filter');
          if (filterEl) filterEl.focus();
        }
        return;
      }
      if (e.key === 'r' || e.key === 'R') {
        if (!e.shiftKey && currentTab === 'traffic' && TrafficTab.selectedId) {
          e.preventDefault();
          TrafficTab.sendToReplay(TrafficTab.selectedId);
          return;
        }
      }
      if (e.shiftKey && (e.key === 'c' || e.key === 'C')) {
        if (currentTab === 'traffic' && TrafficTab.selectedId) {
          e.preventDefault();
          TrafficTab.copyCurl(TrafficTab.selectedId);
          return;
        }
      }
      if (e.key === 'd' || e.key === 'D') {
        if (currentTab === 'traffic' && TrafficTab.selectedId) {
          e.preventDefault();
          TrafficTab.toggleCompare(TrafficTab.selectedId);
          return;
        }
      }
    }

    // Don't trigger when typing in inputs/textareas
    if (isInput) return;

    switch(e.key) {
      case '1': switchTab('traffic'); break;
      case '2': switchTab('replay'); break;
      case '3': switchTab('rules'); break;
      case '4': switchTab('dns'); break;
      case '5': switchTab('intercept'); break;
      case '6': switchTab('analytics'); break;
      case '7': switchTab('cert'); break;
      case '8': switchTab('advanced'); break;
      case '9': switchTab('offensive'); break;
      case '0': switchTab('tools'); break;
      case '?':
        document.getElementById('shortcuts-modal').classList.toggle('hidden');
        break;
      case 'ArrowUp':
        if (currentTab === 'traffic') {
          e.preventDefault();
          TrafficTab.navigateFlow('up');
        }
        break;
      case 'ArrowDown':
        if (currentTab === 'traffic') {
          e.preventDefault();
          TrafficTab.navigateFlow('down');
        }
        break;
      case 'Delete':
        if (currentTab === 'traffic' && TrafficTab.selectedId) {
          TrafficTab.deleteFlow(TrafficTab.selectedId);
        }
        break;
      case 'Escape':
        if (TrafficTab.compareId) TrafficTab.exitCompare();
        document.getElementById('shortcuts-modal').classList.add('hidden');
        break;
    }
  });

  // Init - wait for DOM to be ready
  function init() {
    switchTab('traffic');
    TrafficTab.loadInitial();
    connectWS();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

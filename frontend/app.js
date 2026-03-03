// Tab router + WebSocket client
(function() {
  const content = document.getElementById('tab-content');
  const tabBar = document.getElementById('tab-bar');
  const wsStatus = document.getElementById('ws-status');
  let currentTab = 'traffic';
  let ws = null;

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
      case 'cert':
        content.innerHTML = CertTab.render();
        break;
      case 'tools':
        content.innerHTML = ToolsTab.render();
        break;
    }
  }

  tabBar.addEventListener('click', e => {
    const tab = e.target.dataset?.tab;
    if (tab) switchTab(tab);
  });

  // WebSocket connection
  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws/traffic`);

    ws.onopen = () => {
      wsStatus.className = 'w-2 h-2 rounded-full bg-green-500';
      wsStatus.title = 'Connected';
    };

    ws.onmessage = (event) => {
      try {
        const flow = JSON.parse(event.data);
        TrafficTab.onFlowUpdate(flow);
      } catch (e) { /* ignore */ }
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
    // Don't trigger when typing in inputs/textareas
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
    switch(e.key) {
      case '1': switchTab('traffic'); break;
      case '2': switchTab('replay'); break;
      case '3': switchTab('rules'); break;
      case '4': switchTab('dns'); break;
      case '5': switchTab('intercept'); break;
      case '6': switchTab('cert'); break;
      case '7': switchTab('tools'); break;
    }
  });

  // Init
  switchTab('traffic');
  TrafficTab.loadInitial();
  connectWS();
})();

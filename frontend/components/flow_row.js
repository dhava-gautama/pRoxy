// Render a single flow row for the traffic list
window.FlowRow = {
  statusBadge(code, flowType, method) {
    if (flowType === 'websocket') return '<span class="badge badge-ws">WS</span>';
    if (method === 'DNS') {
      if (code === 0) return '<span class="badge badge-2xx">OK</span>';
      if (code === 3) return '<span class="badge badge-4xx">NXDOMAIN</span>';
      if (code > 0) return '<span class="badge badge-5xx">DNS-' + code + '</span>';
      return '<span class="badge badge-pending">...</span>';
    }
    if (!code) return '<span class="badge badge-pending">...</span>';
    const cls = code < 300 ? 'badge-2xx' : code < 400 ? 'badge-3xx' : code < 500 ? 'badge-4xx' : 'badge-5xx';
    return `<span class="badge ${cls}">${code}</span>`;
  },

  _getHighlightColor(flow, highlightRules) {
    if (!highlightRules || !highlightRules.length) return '';
    for (const rule of highlightRules) {
      if (!rule.enabled) continue;
      let value = '';
      switch (rule.match_type) {
        case 'host': value = flow.host || ''; break;
        case 'path': value = flow.path || ''; break;
        case 'method': value = flow.method || ''; break;
        case 'status': value = String(flow.status_code || ''); break;
        case 'content-type': value = flow.response_content_type || ''; break;
        default: continue;
      }
      try {
        if (new RegExp(rule.pattern, 'i').test(value)) return rule.color;
      } catch (e) { /* invalid regex */ }
    }
    return '';
  },

  dnsBadge(method) {
    if (method === 'doh') return '<span class="badge badge-doh">DoH</span>';
    if (method === 'mapping') return '<span class="badge badge-map">MAP</span>';
    if (method === 'native-dns') return '<span class="badge badge-dns">DNS</span>';
    return '';
  },

  render(flow, isSelected, highlightRules, isCompare) {
    const sel = isSelected ? 'bg-gray-800' : isCompare ? 'bg-indigo-900/30' : 'hover:bg-gray-900';
    const host = flow.host || '';
    const path = flow.path || '/';
    const displayPath = path.length > 50 ? path.substring(0, 50) + '...' : path;
    const wsCount = flow.ws_messages?.length ? `<span class="text-purple-400 text-xs">${flow.ws_messages.length} msgs</span>` : '';
    const hlColor = this._getHighlightColor(flow, highlightRules);
    const hlStyle = hlColor ? `background-color:${hlColor}` : '';
    const size = flow.response_size ? formatBytes(flow.response_size) : '';
    return `
      <div class="flex items-center gap-2 px-3 py-1.5 cursor-pointer border-b border-gray-800/50 ${sel} text-xs"
           data-flow-id="${esc(flow.id)}"
           style="${esc(hlStyle)}"
           onclick="TrafficTab.selectFlow('${esc(flow.id)}')"
           oncontextmenu="TrafficTab.showContextMenu(event, '${esc(flow.id)}')">
        <span class="w-14 text-gray-500 shrink-0">${esc(flow.method)}</span>
        ${this.statusBadge(flow.status_code, flow.flow_type, flow.method)}
        <span class="text-gray-400 shrink-0">${esc(host)}</span>
        <span class="text-gray-500 truncate">${esc(displayPath)}</span>
        ${this.dnsBadge(flow.dns_method)}
        ${flow.intercepted ? '<span class="badge bg-yellow-900 text-yellow-300">INT</span>' : ''}
        ${wsCount}
        <span class="text-gray-600 shrink-0 w-14 text-right">${size}</span>
        <span class="ml-auto text-gray-600 shrink-0 w-14 text-right">${flow.duration_ms ? flow.duration_ms + 'ms' : ''}</span>
      </div>`;
  }
};

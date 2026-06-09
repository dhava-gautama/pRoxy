// Render detailed flow view
window.FlowDetail = {
  render(flow) {
    if (!flow) return '<div class="p-6 text-gray-600 text-center">Select a flow to view details</div>';

    let wsSection = '';
    if (flow.flow_type === 'websocket') {
      const totalSize = (flow.ws_messages || []).reduce((s, m) => s + (m.size || 0), 0);
      const msgList = (flow.ws_messages?.length) ? `
          <div class="bg-gray-900 rounded p-2 text-xs space-y-1 max-h-96 overflow-y-auto" id="ws-messages">
            ${flow.ws_messages.map((m, i) => {
              const ts = m.timestamp ? new Date(m.timestamp * 1000).toLocaleTimeString('en-US', {hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit', fractionalSecondDigits: 3}) : '';
              const sizeStr = m.size ? formatBytes(m.size) : '';
              const isBinary = !m.is_text;
              const c = m.content || '';
              const preview = isBinary && c.startsWith('<binary')
                ? c
                : c.length > 200 ? c.substring(0, 200) + '...' : c;
              const expandable = c.length > 200 || isBinary;
              return `
              <div class="flex gap-2 py-0.5 border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer" onclick="FlowDetail.toggleWSMsg(${i})">
                <span class="text-gray-500 w-20 shrink-0 font-mono">${ts}</span>
                <span class="${m.direction === 'client' ? 'text-blue-400' : 'text-green-400'} w-8 shrink-0">${m.direction === 'client' ? 'OUT' : 'IN'}</span>
                <span class="text-gray-500 w-10 shrink-0">${m.is_text ? 'text' : 'bin'}</span>
                <span class="text-gray-500 w-14 shrink-0 text-right">${sizeStr}</span>
                <span class="text-gray-300 break-all flex-1" id="ws-msg-preview-${i}">${esc(preview)}</span>
                ${expandable ? '<span class="text-gray-600 shrink-0" id="ws-msg-expand-' + i + '">[+]</span>' : ''}
              </div>
              <div class="hidden bg-gray-950 rounded p-2 ml-28 mb-1" id="ws-msg-full-${i}">
                ${isBinary && !c.startsWith('<binary')
                  ? '<pre class="text-gray-400 font-mono text-xs">' + esc(hexDump(c)) + '</pre>'
                  : '<pre class="text-gray-300 break-all whitespace-pre-wrap">' + esc(c) + '</pre>'}
              </div>`;
            }).join('')}
          </div>` : '<div class="text-gray-600 text-xs">No messages yet</div>';

      wsSection = `
        <div>
          <div class="flex items-center justify-between mb-1">
            <h3 class="text-xs font-bold text-gray-400 uppercase">WebSocket Messages (${flow.ws_messages?.length || 0})${totalSize ? ' - ' + formatBytes(totalSize) : ''}</h3>
            <div class="flex items-center gap-2">
              <input type="text" id="ws-filter" placeholder="Filter messages..."
                class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700 w-40 font-mono focus:outline-none focus:border-indigo-500"
                oninput="FlowDetail.filterWSMessages()">
              <select id="ws-dir-filter" onchange="FlowDetail.filterWSMessages()" class="bg-gray-800 text-gray-300 text-xs px-1 py-1 rounded border border-gray-700">
                <option value="all">All</option>
                <option value="client">OUT only</option>
                <option value="server">IN only</option>
              </select>
            </div>
          </div>
          ${msgList}
          <div class="mt-2 flex gap-2">
            <input type="text" id="ws-send-input" placeholder="Message to send..."
              class="flex-1 bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 font-mono focus:outline-none focus:border-indigo-500"
              onkeydown="if(event.key==='Enter')FlowDetail.sendWSMessage('${flow.id}', false)">
            <select id="ws-send-direction" class="bg-gray-800 text-gray-300 text-xs px-2 py-1 rounded border border-gray-700">
              <option value="server">To Server</option>
              <option value="client">To Client</option>
            </select>
            <button onclick="FlowDetail.sendWSMessage('${flow.id}')"
              class="bg-purple-700 hover:bg-purple-600 text-white text-xs px-3 py-1 rounded">Send</button>
          </div>
        </div>`;
    }

    // GraphQL detection
    let graphqlSection = '';
    const isGraphQL = (flow.url || '').includes('/graphql') || this._isGraphQLBody(flow.request_body);
    if (isGraphQL && flow.request_body) {
      graphqlSection = this._renderGraphQL(flow.request_body);
    }

    // Protobuf detection for request
    let requestBodySection = '';
    if (flow.request_body) {
      if (this._isProtobuf(flow.request_body, flow.request_content_type)) {
        requestBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Body <span class="text-cyan-400">(Protobuf)</span></h3>
          <div class="bg-gray-900 rounded p-2 text-xs" id="protobuf-request-${flow.id}">
            ${this._renderProtobufAuto(flow.id, 'request', flow.request_body)}
          </div>
        </div>`;
      } else if (this._isBinary(flow.request_body)) {
        requestBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Body <span class="text-cyan-400">(Binary)</span></h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-400 font-mono">${esc(hexDump(flow.request_body))}</pre>
        </div>`;
      } else {
        requestBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Body</h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${this._formatBody(flow.request_body, flow.request_content_type)}</pre>
        </div>`;
      }
    }

    // Response body: protobuf, JSON auto-format, binary hex, or raw
    let responseBodySection = '';
    if (flow.completed && flow.response_body) {
      if (this._isProtobuf(flow.response_body, flow.response_content_type)) {
        responseBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body <span class="text-cyan-400">(Protobuf)</span></h3>
          <div class="bg-gray-900 rounded p-2 text-xs" id="protobuf-response-${flow.id}">
            ${this._renderProtobufAuto(flow.id, 'response', flow.response_body)}
          </div>
        </div>`;
      } else if (this._isBinary(flow.response_body)) {
        responseBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body <span class="text-cyan-400">(Binary)</span></h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-400 font-mono">${esc(hexDump(flow.response_body))}</pre>
        </div>`;
      } else {
        const sizeStr = flow.response_size ? ` (${formatBytes(flow.response_size)})` : '';
        responseBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body${sizeStr}</h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${this._formatBody(flow.response_body, flow.response_content_type)}</pre>
        </div>`;
      }
    }

    return `
      <div class="p-4 space-y-4">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="font-bold text-white">${flow.method}</span>
          ${FlowRow.statusBadge(flow.status_code, flow.flow_type)}
          <span class="text-gray-400 break-all">${esc(flow.url)}</span>
          <button onclick="TrafficTab.sendToReplay('${flow.id}')" class="ml-auto text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-1 rounded" title="Ctrl+R">Replay</button>
          <button onclick="TrafficTab.copyCurl('${flow.id}')" class="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded" title="Ctrl+Shift+C">cURL</button>
          <button onclick="TrafficTab.toggleCompare('${flow.id}')" class="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded" title="Ctrl+D">Compare</button>
        </div>

        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Headers</h3>
          <div class="bg-gray-900 rounded p-2 text-xs space-y-0.5">
            ${Object.entries(flow.request_headers || {}).map(([k, v]) =>
              `<div><span class="text-indigo-400">${esc(k)}</span>: <span class="text-gray-300">${esc(v)}</span></div>`
            ).join('')}
          </div>
        </div>

        ${requestBodySection}
        ${graphqlSection}

        ${flow.completed ? `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Headers</h3>
          <div class="bg-gray-900 rounded p-2 text-xs space-y-0.5">
            ${Object.entries(flow.response_headers || {}).map(([k, v]) =>
              `<div><span class="text-green-400">${esc(k)}</span>: <span class="text-gray-300">${esc(v)}</span></div>`
            ).join('')}
          </div>
        </div>

        ${responseBodySection}

        <div class="text-xs text-gray-600">
          Duration: ${flow.duration_ms}ms${flow.response_size ? ' | Size: ' + formatBytes(flow.response_size) : ''}
        </div>
        ` : '<div class="text-yellow-500 text-xs">Response pending...</div>'}

        ${wsSection}
      </div>`;
  },

  // Render diff/compare view between two flows
  renderDiff(flowA, flowB) {
    if (!flowA || !flowB) return '<div class="p-6 text-gray-600 text-center">Select two flows to compare</div>';

    const reqDiff = this._diffHeaders(flowA.request_headers, flowB.request_headers);
    const respDiff = this._diffHeaders(flowA.response_headers || {}, flowB.response_headers || {});
    const bodyDiffResult = lineDiff(
      this._tryFormatJSON(flowA.response_body || '', flowA.response_content_type),
      this._tryFormatJSON(flowB.response_body || '', flowB.response_content_type)
    );

    return `
      <div class="p-4 space-y-4">
        <div class="flex items-center gap-2">
          <span class="text-indigo-400 font-bold">Comparing</span>
          <span class="text-xs text-gray-400">${esc(flowA.method)} ${esc(flowA.url)}</span>
          <span class="text-gray-500">vs</span>
          <span class="text-xs text-gray-400">${esc(flowB.method)} ${esc(flowB.url)}</span>
          <button onclick="TrafficTab.exitCompare()" class="ml-auto text-xs bg-red-700 hover:bg-red-600 text-white px-2 py-1 rounded">Exit Compare</button>
        </div>

        <div class="flex gap-2 text-xs">
          <span class="text-gray-500">Status:</span>
          <span class="${flowA.status_code === flowB.status_code ? 'text-gray-300' : 'text-yellow-400'}">
            ${flowA.status_code} vs ${flowB.status_code}
          </span>
          <span class="text-gray-500 ml-4">Duration:</span>
          <span class="${flowA.duration_ms === flowB.duration_ms ? 'text-gray-300' : 'text-yellow-400'}">
            ${flowA.duration_ms}ms vs ${flowB.duration_ms}ms
          </span>
        </div>

        ${reqDiff ? `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Header Differences</h3>
          <div class="bg-gray-900 rounded p-2 text-xs">${reqDiff}</div>
        </div>` : ''}

        ${respDiff ? `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Header Differences</h3>
          <div class="bg-gray-900 rounded p-2 text-xs">${respDiff}</div>
        </div>` : ''}

        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body Diff</h3>
          <div class="flex gap-0">
            <pre class="body-preview bg-gray-900 rounded-l p-2 text-xs flex-1 border-r border-gray-700">${bodyDiffResult.left.map(l =>
              l.type === 'removed' ? `<span class="diff-removed">${esc(l.text)}</span>` :
              l.type === 'empty' ? '' : esc(l.text)
            ).join('\n')}</pre>
            <pre class="body-preview bg-gray-900 rounded-r p-2 text-xs flex-1">${bodyDiffResult.right.map(l =>
              l.type === 'added' ? `<span class="diff-added">${esc(l.text)}</span>` :
              l.type === 'empty' ? '' : esc(l.text)
            ).join('\n')}</pre>
          </div>
        </div>
      </div>`;
  },

  _diffHeaders(a, b) {
    const allKeys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})]);
    const diffs = [];
    for (const key of allKeys) {
      const va = (a || {})[key];
      const vb = (b || {})[key];
      if (va === vb) continue;
      if (va && !vb) {
        diffs.push(`<div class="diff-removed"><span class="text-red-400">- ${esc(key)}</span>: ${esc(va)}</div>`);
      } else if (!va && vb) {
        diffs.push(`<div class="diff-added"><span class="text-green-400">+ ${esc(key)}</span>: ${esc(vb)}</div>`);
      } else {
        diffs.push(`<div class="diff-removed"><span class="text-red-400">- ${esc(key)}</span>: ${esc(va)}</div>`);
        diffs.push(`<div class="diff-added"><span class="text-green-400">+ ${esc(key)}</span>: ${esc(vb)}</div>`);
      }
    }
    return diffs.length ? diffs.join('') : '';
  },

  // ── Body formatting ──────────────────────────────────────

  _isBinary(body) {
    return body && body.startsWith('<binary ');
  },

  _formatBody(body, contentType) {
    if (!body) return '';
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('json')) {
      const formatted = this._tryFormatJSON(body, contentType);
      return highlightJSON(formatted);
    }
    return esc(body);
  },

  // ── GraphQL ─────────────────────────────────────────────

  _isGraphQLBody(body) {
    if (!body) return false;
    try {
      const parsed = JSON.parse(body);
      return typeof parsed.query === 'string';
    } catch { return false; }
  },

  _renderGraphQL(body) {
    try {
      const parsed = JSON.parse(body);
      if (!parsed.query) return '';
      const formatted = this._formatGraphQLQuery(parsed.query);
      let html = `
        <div style="border-left:3px solid #7c3aed" class="pl-3">
          <h3 class="text-xs font-bold text-purple-400 uppercase mb-1">GraphQL${parsed.operationName ? ' — ' + esc(parsed.operationName) : ''}</h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-purple-200" style="max-height:300px">${esc(formatted)}</pre>`;
      if (parsed.variables && Object.keys(parsed.variables).length) {
        html += `
          <h4 class="text-xs font-bold text-purple-400 mt-2 mb-1">Variables</h4>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${highlightJSON(JSON.stringify(parsed.variables, null, 2))}</pre>`;
      }
      html += '</div>';
      return html;
    } catch { return ''; }
  },

  _formatGraphQLQuery(query) {
    let result = '';
    let depth = 0;
    let inString = false;
    const indent = () => '  '.repeat(depth);
    for (let i = 0; i < query.length; i++) {
      const ch = query[i];
      if (ch === '"' && query[i-1] !== '\\') { inString = !inString; result += ch; continue; }
      if (inString) { result += ch; continue; }
      if (ch === '{') { depth++; result += '{\n' + indent(); continue; }
      if (ch === '}') { depth--; result += '\n' + indent() + '}'; continue; }
      if (ch === '\n') { result += '\n' + indent(); continue; }
      result += ch;
    }
    return result.trim();
  },

  // ── JSON auto-format ───────────────────────────────────

  _tryFormatJSON(body, contentType) {
    if (!body) return body;
    const ct = (contentType || '').toLowerCase();
    if (!ct.includes('json')) return body;
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch { return body; }
  },

  // ── Protobuf Decoding ─────────────────────────────────

  _isProtobuf(body, contentType) {
    if (!body) return false;
    const ct = (contentType || '').toLowerCase();
    // Check for various protobuf indicators
    return (body.startsWith('base64:') && (ct.includes('grpc') || ct.includes('protobuf') || ct.includes('x-protobuf'))) ||
           ct.includes('grpc') || ct.includes('protobuf');
  },

  _renderProtobuf(body) {
    try {
      // Handle different body formats
      let bytes;
      if (body.startsWith('base64:')) {
        const b64 = body.substring(7);
        const raw = atob(b64);
        bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      } else if (typeof body === 'string' && /^[0-9a-fA-F\s]+$/.test(body.replace(/\s/g, ''))) {
        // Handle hex string
        const hex = body.replace(/\s/g, '');
        bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
      } else {
        // Handle raw binary
        bytes = new TextEncoder().encode(body);
      }

      // Skip gRPC 5-byte frame header if present
      let offset = 0;
      if (bytes.length > 5 && (bytes[0] === 0 || bytes[0] === 1)) {
        const len = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
        if (len === bytes.length - 5) offset = 5;
      }

      const fields = this._decodeProtobufFields(bytes, offset, bytes.length);
      if (fields.length === 0) {
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
        return `
          <div class="text-gray-500">No protobuf fields decoded. Raw hex:</div>
          <div class="text-gray-400 break-all mt-1 font-mono">${hex}</div>
        `;
      }

      // Enhanced rendering with better formatting
      return `
        <div class="protobuf-decoded">
          <div class="text-xs text-gray-500 mb-2">📋 Decoded Protobuf Fields:</div>
          ${this._renderProtobufTree(fields, 0)}
        </div>
      `;
    } catch (e) {
      return `<span class="text-red-400">Protobuf decode error: ${esc(e.message)}</span>`;
    }
  },

  _decodeProtobufFields(bytes, start, end) {
    const fields = [];
    let pos = start;
    while (pos < end) {
      const tagResult = this._readVarint(bytes, pos);
      if (!tagResult) break;
      const tag = tagResult.value;
      pos = tagResult.pos;
      const fieldNumber = tag >>> 3;
      const wireType = tag & 0x7;

      if (fieldNumber === 0) break;

      switch (wireType) {
        case 0: {
          const vr = this._readVarint(bytes, pos);
          if (!vr) { pos = end; break; }
          fields.push({ field: fieldNumber, type: 'varint', value: vr.value });
          pos = vr.pos;
          break;
        }
        case 1: {
          if (pos + 8 > end) { pos = end; break; }
          const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 8);
          fields.push({ field: fieldNumber, type: '64-bit', value: v.getFloat64(0, true) });
          pos += 8;
          break;
        }
        case 2: {
          const lr = this._readVarint(bytes, pos);
          if (!lr || lr.pos + lr.value > end) { pos = end; break; }
          const data = bytes.slice(lr.pos, lr.pos + lr.value);
          pos = lr.pos + lr.value;
          let strVal = null;
          let nested = null;
          try {
            const decoded = new TextDecoder('utf-8', { fatal: true }).decode(data);
            if (/^[\x20-\x7e\n\r\t]*$/.test(decoded) && decoded.length > 0) strVal = decoded;
          } catch {}
          if (!strVal) {
            try {
              const sub = this._decodeProtobufFields(data, 0, data.length);
              if (sub.length > 0) nested = sub;
            } catch {}
          }
          if (nested && nested.length > 0) {
            fields.push({ field: fieldNumber, type: 'message', value: nested });
          } else if (strVal !== null) {
            fields.push({ field: fieldNumber, type: 'string', value: strVal });
          } else {
            const hex = Array.from(data).map(b => b.toString(16).padStart(2,'0')).join(' ');
            fields.push({ field: fieldNumber, type: 'bytes', value: hex });
          }
          break;
        }
        case 5: {
          if (pos + 4 > end) { pos = end; break; }
          const v32 = new DataView(bytes.buffer, bytes.byteOffset + pos, 4);
          fields.push({ field: fieldNumber, type: '32-bit', value: v32.getFloat32(0, true) });
          pos += 4;
          break;
        }
        default:
          pos = end;
      }
    }
    return fields;
  },

  _readVarint(bytes, pos) {
    let result = 0;
    let shift = 0;
    while (pos < bytes.length) {
      const b = bytes[pos++];
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) return { value: result >>> 0, pos };
      shift += 7;
      if (shift > 35) return null;
    }
    return null;
  },

  _renderProtobufTree(fields, depth) {
    const indent = '  '.repeat(depth);
    return fields.map(f => {
      const fieldHtml = `<span class="text-yellow-400">field ${f.field}</span>`;
      const typeHtml = `<span class="text-gray-500">(${f.type})</span>`;
      if (f.type === 'message') {
        return `<div>${indent}${fieldHtml} ${typeHtml}:</div>${this._renderProtobufTree(f.value, depth + 1)}`;
      } else if (f.type === 'string') {
        return `<div>${indent}${fieldHtml} ${typeHtml}: <span class="text-green-400">"${esc(f.value)}"</span></div>`;
      } else if (f.type === 'varint') {
        return `<div>${indent}${fieldHtml} ${typeHtml}: <span class="text-blue-400">${f.value}</span></div>`;
      } else {
        return `<div>${indent}${fieldHtml} ${typeHtml}: <span class="text-gray-300">${esc(String(f.value))}</span></div>`;
      }
    }).join('');
  },

  // ── WebSocket Message Injection ───────────────────────────

  toggleWSMsg(idx) {
    const full = document.getElementById(`ws-msg-full-${idx}`);
    const expand = document.getElementById(`ws-msg-expand-${idx}`);
    if (!full) return;
    const hidden = full.classList.toggle('hidden');
    if (expand) expand.textContent = hidden ? '[+]' : '[-]';
  },

  _renderProtobufAuto(flowId, section, body) {
    // Start with basic decoding immediately
    let html = this._renderProtobuf(body);

    // Automatically load enhanced decoding in the background
    setTimeout(async () => {
      try {
        const response = await authFetch(`/api/flows/${flowId}/protobuf`);
        if (!response.ok) return; // Silently fail if enhanced decoding not available

        const decoded = await response.json();
        const containerEl = document.getElementById(`protobuf-${section}-${flowId}`);
        if (!containerEl) return;

        const protobufData = section === 'request' ? decoded.request : decoded.response;

        // Update with enhanced decoding
        const serviceInfo = `
          <div class="mb-3 p-2 bg-indigo-900/20 border border-indigo-700 rounded text-xs">
            <div class="text-indigo-300 font-bold">🚀 ${decoded.service}</div>
            <div class="text-indigo-300">📡 ${decoded.method}</div>
          </div>
        `;

        containerEl.innerHTML = serviceInfo + this._renderEnhancedProtobuf(protobufData);
      } catch (error) {
        // Silently fail - keep basic decoding if enhanced fails
        console.debug('Enhanced protobuf decoding not available:', error.message);
      }
    }, 100);

    return html;
  },


  _renderEnhancedProtobuf(data) {
    if (!data || Object.keys(data).length === 0) {
      return '<div class="text-gray-500">📭 Empty message</div>';
    }

    let html = '<div class="space-y-2">';

    for (const [fieldName, fieldInfo] of Object.entries(data)) {
      const fieldNumber = fieldInfo.field_number || '?';
      const fieldType = fieldInfo.type || 'unknown';
      const fieldValue = fieldInfo.value;

      // Clean field name display
      const displayName = fieldName.replace(/_/g, ' ').replace(/field /, '');

      html += `
        <div class="border-l-2 border-gray-600 pl-3">
          <div class="flex items-center gap-2">
            <span class="text-yellow-400 font-mono text-xs bg-gray-800 px-1 rounded">${fieldNumber}</span>
            <span class="text-blue-400 text-xs">${displayName}</span>
            <span class="text-gray-500 text-xs">(${fieldType})</span>
          </div>
          <div class="mt-1 ml-2">
            ${this._renderProtobufValue(fieldValue, fieldType)}
          </div>
        </div>
      `;
    }

    html += '</div>';
    return html;
  },

  _renderProtobufValue(value, type) {
    if (value === null || value === undefined) {
      return '<span class="text-gray-500 italic">null</span>';
    }

    switch (type) {
      case 'bool':
        return `<span class="text-${value ? 'green' : 'red'}-400 font-bold">${value}</span>`;

      case 'string':
        return `<span class="text-green-400">"${esc(value)}"</span>`;

      case 'int32':
      case 'int64':
      case 'varint':
        return `<span class="text-blue-400">${value}</span>`;

      case 'bytes':
        return `<span class="text-gray-400 font-mono">${value}</span>`;

      case 'message':
        if (typeof value === 'object') {
          return this._renderEnhancedProtobuf(value);
        }
        return `<span class="text-gray-300">${JSON.stringify(value)}</span>`;

      default:
        if (typeof value === 'string') {
          return `<span class="text-gray-300">"${esc(value)}"</span>`;
        } else if (typeof value === 'number') {
          return `<span class="text-blue-400">${value}</span>`;
        } else if (typeof value === 'boolean') {
          return `<span class="text-${value ? 'green' : 'red'}-400">${value}</span>`;
        } else {
          return `<span class="text-gray-300">${JSON.stringify(value)}</span>`;
        }
    }
  },

  filterWSMessages() {
    const filter = (document.getElementById('ws-filter')?.value || '').toLowerCase();
    const dirFilter = document.getElementById('ws-dir-filter')?.value || 'all';
    const container = document.getElementById('ws-messages');
    if (!container) return;
    // Each message is a pair of elements: the row div and the expandable div
    const children = Array.from(container.children);
    for (let i = 0; i < children.length; i += 2) {
      const row = children[i];
      const detail = children[i + 1];
      const text = row.textContent.toLowerCase();
      const isOut = row.querySelector('.text-blue-400');
      const dir = isOut ? 'client' : 'server';
      const matchDir = dirFilter === 'all' || dir === dirFilter;
      const matchText = !filter || text.includes(filter);
      const show = matchDir && matchText;
      row.style.display = show ? '' : 'none';
      if (detail) detail.style.display = show && !detail.classList.contains('hidden') ? '' : 'none';
    }
  },

  async sendWSMessage(flowId) {
    const input = document.getElementById('ws-send-input');
    const dirSelect = document.getElementById('ws-send-direction');
    if (!input || !input.value.trim()) { Toast.show('Enter a message', 'warn'); return; }

    const content = input.value;
    const toClient = dirSelect?.value === 'client';

    try {
      const resp = await authFetch(`/api/flows/${flowId}/ws/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, to_client: toClient })
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        Toast.show(err.detail || 'WS send failed', 'error');
        return;
      }
      Toast.show('Message sent', 'success');
      input.value = '';

      // Append to visible message list
      const msgContainer = document.getElementById('ws-messages');
      if (msgContainer) {
        const direction = toClient ? 'server' : 'client';
        const color = direction === 'client' ? 'text-blue-400' : 'text-green-400';
        const label = direction === 'client' ? 'OUT' : 'IN';
        const div = document.createElement('div');
        div.className = 'flex gap-2';
        div.innerHTML = `
          <span class="${color} w-12 shrink-0">${label}</span>
          <span class="text-gray-400 w-16 shrink-0">text</span>
          <span class="text-yellow-300 break-all">[injected] ${esc(content.substring(0, 500))}</span>`;
        msgContainer.appendChild(div);
        msgContainer.scrollTop = msgContainer.scrollHeight;
      }
    } catch (e) {
      Toast.show('WS send failed: ' + e.message, 'error');
    }
  }
};

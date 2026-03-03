// Render detailed flow view
window.FlowDetail = {
  render(flow) {
    if (!flow) return '<div class="p-6 text-gray-600 text-center">Select a flow to view details</div>';

    let wsSection = '';
    if (flow.flow_type === 'websocket' && flow.ws_messages?.length) {
      wsSection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">WebSocket Messages (${flow.ws_messages.length})</h3>
          <div class="bg-gray-900 rounded p-2 text-xs space-y-1 max-h-96 overflow-y-auto">
            ${flow.ws_messages.map(m => `
              <div class="flex gap-2">
                <span class="${m.direction === 'client' ? 'text-blue-400' : 'text-green-400'} w-12 shrink-0">${m.direction === 'client' ? 'OUT' : 'IN'}</span>
                <span class="text-gray-400 w-16 shrink-0">${m.is_text ? 'text' : 'bin'}</span>
                <span class="text-gray-300 break-all">${esc(m.content.substring(0, 500))}</span>
              </div>
            `).join('')}
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
          <div class="bg-gray-900 rounded p-2 text-xs">${this._renderProtobuf(flow.request_body)}</div>
        </div>`;
      } else {
        requestBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Request Body</h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${esc(flow.request_body)}</pre>
        </div>`;
      }
    }

    // Response body: protobuf, JSON auto-format, or raw
    let responseBodySection = '';
    if (flow.completed && flow.response_body) {
      if (this._isProtobuf(flow.response_body, flow.response_content_type)) {
        responseBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body <span class="text-cyan-400">(Protobuf)</span></h3>
          <div class="bg-gray-900 rounded p-2 text-xs">${this._renderProtobuf(flow.response_body)}</div>
        </div>`;
      } else {
        const formatted = this._tryFormatJSON(flow.response_body, flow.response_content_type);
        responseBodySection = `
        <div>
          <h3 class="text-xs font-bold text-gray-400 uppercase mb-1">Response Body</h3>
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${esc(formatted)}</pre>
        </div>`;
      }
    }

    return `
      <div class="p-4 space-y-4">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="font-bold text-white">${flow.method}</span>
          ${FlowRow.statusBadge(flow.status_code, flow.flow_type)}
          <span class="text-gray-400 break-all">${esc(flow.url)}</span>
          <button onclick="TrafficTab.sendToReplay('${flow.id}')" class="ml-auto text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-1 rounded">Replay</button>
          <button onclick="TrafficTab.copyCurl('${flow.id}')" class="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded">cURL</button>
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
          Duration: ${flow.duration_ms}ms
        </div>
        ` : '<div class="text-yellow-500 text-xs">Response pending...</div>'}

        ${wsSection}
      </div>`;
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
          <pre class="body-preview bg-gray-900 rounded p-2 text-xs text-gray-300">${esc(JSON.stringify(parsed.variables, null, 2))}</pre>`;
      }
      html += '</div>';
      return html;
    } catch { return ''; }
  },

  _formatGraphQLQuery(query) {
    // Simple indentation based on brace depth
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
    return body.startsWith('base64:') && (ct.includes('grpc') || ct.includes('protobuf') || ct.includes('x-protobuf'));
  },

  _renderProtobuf(body) {
    try {
      const b64 = body.substring(7); // strip "base64:"
      const raw = atob(b64);
      let bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

      // Skip gRPC 5-byte frame header (compressed flag + 4-byte length)
      let offset = 0;
      if (bytes.length > 5 && (bytes[0] === 0 || bytes[0] === 1)) {
        const len = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
        if (len === bytes.length - 5) offset = 5;
      }

      const fields = this._decodeProtobufFields(bytes, offset, bytes.length);
      if (fields.length === 0) {
        // No valid fields — show hex dump fallback
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
        return `<div class="text-gray-500">No protobuf fields decoded. Raw hex:</div><div class="text-gray-400 break-all mt-1">${hex}</div>`;
      }
      return this._renderProtobufTree(fields, 0);
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

      if (fieldNumber === 0) break; // invalid

      switch (wireType) {
        case 0: { // varint
          const vr = this._readVarint(bytes, pos);
          if (!vr) { pos = end; break; }
          fields.push({ field: fieldNumber, type: 'varint', value: vr.value });
          pos = vr.pos;
          break;
        }
        case 1: { // 64-bit
          if (pos + 8 > end) { pos = end; break; }
          const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 8);
          fields.push({ field: fieldNumber, type: '64-bit', value: v.getFloat64(0, true) });
          pos += 8;
          break;
        }
        case 2: { // length-delimited
          const lr = this._readVarint(bytes, pos);
          if (!lr || lr.pos + lr.value > end) { pos = end; break; }
          const data = bytes.slice(lr.pos, lr.pos + lr.value);
          pos = lr.pos + lr.value;
          // Try as nested message first (only if it doesn't look like printable text)
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
        case 5: { // 32-bit
          if (pos + 4 > end) { pos = end; break; }
          const v32 = new DataView(bytes.buffer, bytes.byteOffset + pos, 4);
          fields.push({ field: fieldNumber, type: '32-bit', value: v32.getFloat32(0, true) });
          pos += 4;
          break;
        }
        default:
          pos = end; // unknown wire type, stop
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
      if (shift > 35) return null; // too many bytes
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
  }
};

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Encoder/Decoder Tools tab
window.ToolsTab = {
  render() {
    return `
      <div class="max-w-5xl mx-auto p-6 space-y-4 overflow-y-auto" style="height:calc(100vh - 56px)">
        <h2 class="text-lg font-bold text-white">Encoder / Decoder Tools</h2>
        <div class="flex flex-wrap gap-2">
          <button onclick="ToolsTab.op('base64enc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Base64 Encode</button>
          <button onclick="ToolsTab.op('base64dec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Base64 Decode</button>
          <button onclick="ToolsTab.op('urlenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">URL Encode</button>
          <button onclick="ToolsTab.op('urldec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">URL Decode</button>
          <button onclick="ToolsTab.op('htmlenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">HTML Encode</button>
          <button onclick="ToolsTab.op('htmldec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">HTML Decode</button>
          <button onclick="ToolsTab.op('hexenc')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Hex Encode</button>
          <button onclick="ToolsTab.op('hexdec')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">Hex Decode</button>
          <button onclick="ToolsTab.op('jwt')" class="text-xs bg-indigo-700 hover:bg-indigo-600 text-white px-3 py-1.5 rounded">JWT Decode</button>
          <button onclick="ToolsTab.op('md5')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">MD5</button>
          <button onclick="ToolsTab.op('sha1')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">SHA-1</button>
          <button onclick="ToolsTab.op('sha256')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded">SHA-256</button>
        </div>
        <div class="flex gap-4" style="height:calc(100vh - 220px)">
          <div class="flex-1 flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Input</label>
            <textarea id="tools-input" class="flex-1 bg-gray-900 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 font-mono resize-none focus:outline-none focus:border-indigo-500" placeholder="Paste text here..."></textarea>
          </div>
          <div class="flex-1 flex flex-col">
            <label class="text-xs text-gray-400 mb-1">Output</label>
            <textarea id="tools-output" class="flex-1 bg-gray-900 text-gray-300 text-xs px-3 py-2 rounded border border-gray-700 font-mono resize-none focus:outline-none" readonly></textarea>
          </div>
        </div>
      </div>`;
  },

  async op(name) {
    const input = document.getElementById('tools-input').value;
    const output = document.getElementById('tools-output');
    try {
      switch (name) {
        case 'base64enc': output.value = btoa(unescape(encodeURIComponent(input))); break;
        case 'base64dec': output.value = decodeURIComponent(escape(atob(input.trim()))); break;
        case 'urlenc': output.value = encodeURIComponent(input); break;
        case 'urldec': output.value = decodeURIComponent(input); break;
        case 'htmlenc': output.value = input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); break;
        case 'htmldec': { const t = document.createElement('textarea'); t.innerHTML = input; output.value = t.value; break; }
        case 'hexenc': output.value = Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2,'0')).join(''); break;
        case 'hexdec': {
          const hex = input.replace(/\s/g, '');
          const bytes = new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
          output.value = new TextDecoder().decode(bytes);
          break;
        }
        case 'jwt': {
          const parts = input.trim().split('.');
          if (parts.length < 2) { output.value = 'Invalid JWT'; break; }
          const header = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')))));
          const payload = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))));
          output.value = 'Header:\n' + JSON.stringify(header, null, 2) + '\n\nPayload:\n' + JSON.stringify(payload, null, 2);
          break;
        }
        case 'md5': output.value = await this._md5(input); break;
        case 'sha1': output.value = await this._hash('SHA-1', input); break;
        case 'sha256': output.value = await this._hash('SHA-256', input); break;
      }
    } catch (e) {
      output.value = 'Error: ' + e.message;
    }
  },

  async _hash(algo, str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest(algo, data);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  },

  async _md5(str) {
    // Simple MD5 implementation
    const k = [], s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    for (let i = 0; i < 64; i++) k[i] = Math.floor(2**32 * Math.abs(Math.sin(i + 1))) >>> 0;

    const bytes = new TextEncoder().encode(str);
    const bits = bytes.length * 8;
    const padded = new Uint8Array(((bytes.length + 8 >> 6) + 1) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, bits & 0xFFFFFFFF, true);
    view.setUint32(padded.length - 4, Math.floor(bits / 2**32), true);

    let a0 = 0x67452301 >>> 0, b0 = 0xefcdab89 >>> 0, c0 = 0x98badcfe >>> 0, d0 = 0x10325476 >>> 0;
    for (let off = 0; off < padded.length; off += 64) {
      const M = [];
      for (let j = 0; j < 16; j++) M[j] = view.getUint32(off + j * 4, true);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i+5) % 16; }
        else { F = C ^ (B | ~D); g = (7*i) % 16; }
        F = (F + A + k[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    return [a0, b0, c0, d0].map(v => {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, v, true);
      return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
    }).join('');
  }
};

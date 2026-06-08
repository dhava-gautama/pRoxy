// Shared utilities used across all tabs and components
window.esc = function(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
};

// Authentication utilities
window.getAuthKey = function() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('key') || '';
};

window.authFetch = function(url, options = {}) {
  const key = getAuthKey();
  if (!key) {
    // If no key, try the request anyway (for when auth is disabled)
    return fetch(url, options);
  }

  // Add auth key to URL
  const separator = url.includes('?') ? '&' : '?';
  const authUrl = `${url}${separator}key=${encodeURIComponent(key)}`;
  return fetch(authUrl, options);
};

window.debounce = function(fn, ms) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
};

window.copyToClipboard = async function(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
};

window.formatBytes = function(bytes) {
  if (!bytes || bytes === 0) return '';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
};

// Simple JSON syntax highlighter (returns HTML)
// Runs regexes on raw JSON first, then escapes non-highlighted parts
window.highlightJSON = function(json) {
  if (!json) return '';
  // Tokenize: find JSON keys, string values, numbers, booleans, nulls
  // Replace with placeholders, then escape the rest
  const tokens = [];
  const placeholder = function(cls, text) {
    const idx = tokens.length;
    tokens.push('<span class="' + cls + '">' + esc(text) + '</span>');
    return '\x00T' + idx + '\x00';
  };
  let result = json
    // Keys
    .replace(/"([^"\\]*(\\.[^"\\]*)*)"\s*:/g, function(m, key) {
      return placeholder('text-indigo-400', '"' + key + '"') + ':';
    })
    // String values (after colon)
    .replace(/:\s*"([^"\\]*(\\.[^"\\]*)*)"/g, function(m, val) {
      return ': ' + placeholder('text-green-400', '"' + val + '"');
    })
    // Numbers
    .replace(/:\s*(-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g, function(m, val) {
      return ': ' + placeholder('text-blue-400', val);
    })
    // Booleans
    .replace(/:\s*(true|false)/g, function(m, val) {
      return ': ' + placeholder('text-yellow-400', val);
    })
    // Null
    .replace(/:\s*(null)/g, function(m, val) {
      return ': ' + placeholder('text-red-400', val);
    });
  // Escape remaining text (brackets, commas, whitespace, etc.)
  result = result.replace(/[^\x00]+/g, function(chunk) {
    // Don't escape placeholder markers
    return esc(chunk);
  });
  // Restore tokens
  result = result.replace(/\x00T(\d+)\x00/g, function(m, idx) {
    return tokens[parseInt(idx)];
  });
  return result;
};

// Hex dump for binary data
window.hexDump = function(str, maxBytes) {
  maxBytes = maxBytes || 512;
  const lines = [];
  const len = Math.min(str.length, maxBytes);
  for (let i = 0; i < len; i += 16) {
    const slice = str.slice(i, i + 16);
    const hex = [];
    const ascii = [];
    for (let j = 0; j < 16; j++) {
      if (j < slice.length) {
        const code = slice.charCodeAt(j);
        hex.push(code.toString(16).padStart(2, '0'));
        ascii.push(code >= 32 && code < 127 ? slice[j] : '.');
      } else {
        hex.push('  ');
        ascii.push(' ');
      }
    }
    const offset = i.toString(16).padStart(8, '0');
    lines.push(`${offset}  ${hex.slice(0,8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
  }
  if (str.length > maxBytes) {
    lines.push(`... (${str.length - maxBytes} more bytes)`);
  }
  return lines.join('\n');
};

// Simple line diff between two strings
window.lineDiff = function(a, b) {
  const aLines = (a || '').split('\n');
  const bLines = (b || '').split('\n');
  const result = { left: [], right: [] };
  const maxLen = Math.max(aLines.length, bLines.length);
  for (let i = 0; i < maxLen; i++) {
    const al = i < aLines.length ? aLines[i] : null;
    const bl = i < bLines.length ? bLines[i] : null;
    if (al === bl) {
      result.left.push({ text: al, type: 'same' });
      result.right.push({ text: bl, type: 'same' });
    } else {
      result.left.push({ text: al, type: al === null ? 'empty' : 'removed' });
      result.right.push({ text: bl, type: bl === null ? 'empty' : 'added' });
    }
  }
  return result;
};

// Theme management
window.ThemeManager = {
  current: localStorage.getItem('pRoxy-theme') || 'dark',

  init() {
    this.apply(this.current);
  },

  toggle() {
    this.current = this.current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('pRoxy-theme', this.current);
    this.apply(this.current);
  },

  apply(theme) {
    const html = document.documentElement;
    if (theme === 'light') {
      html.classList.remove('dark');
      html.classList.add('light');
      document.body.className = 'h-full text-gray-800 font-mono text-sm bg-gray-100';
    } else {
      html.classList.add('dark');
      html.classList.remove('light');
      document.body.className = 'h-full dark text-gray-300 font-mono text-sm';
    }
  }
};

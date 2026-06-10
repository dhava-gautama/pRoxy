# Custom addon scripts

Drop a mitmproxy addon (`*.py`) in this directory and it's **auto-loaded at proxy
startup** with full hooks and hot-reload (edits to a loaded file reload live).

- Files starting with `_` (like `_example_addon.py`) are **ignored** — use the
  prefix for templates/helpers you don't want loaded.
- You can also load scripts from anywhere by adding absolute paths to the
  `custom_scripts` setting (Settings API or the **Scripts** dashboard tab).
- Adding/removing a script requires a proxy **restart** to take effect; editing an
  already-loaded script hot-reloads automatically.
- In dual mode the script is loaded by both the HTTP and WireGuard instances, so a
  module-level singleton will exist once per instance — keep addon state per-flow.

## Minimal addon

```python
import logging

class Tagger:
    def request(self, flow):
        flow.request.headers["X-pRoxy"] = "1"

    def response(self, flow):
        logging.info("%s -> %s", flow.request.pretty_url, flow.response.status_code)

addons = [Tagger()]
```

Available hooks (mitmproxy 12.x): `request`, `requestheaders`, `response`,
`responseheaders`, `websocket_message`, `tls_clienthello`, `error`, etc.
See https://docs.mitmproxy.org/stable/addons-overview/

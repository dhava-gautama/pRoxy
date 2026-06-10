"""
MinionRush Ad Reward Bypass — mitmproxy addon
=============================================
Intercepts Gameloft ad responses from a314.gameloft.com and injects
JavaScript that immediately fires the in-game reward URL scheme
(exit:checkreward:tokens:delivered:1) without waiting for the video.

Setup:
  1. Run:  /tmp/mitm_venv/bin/mitmproxy -s minion_bypass.py --listen-port 8080
     Or:   /tmp/mitm_venv/bin/mitmdump  -s minion_bypass.py --listen-port 8080
  2. On iOS device: Settings → Wi-Fi → (your network) → Configure Proxy → Manual
     Host: <this machine's LAN IP>   Port: 8080
  3. On iOS: open http://mitm.it and install the mitmproxy CA certificate
     (Settings → General → VPN & Device Management → trust it)
  4. Launch Minion Rush, trigger an ad (multiply tokens screen, revive screen, etc.)
  5. Watch the reward fire immediately — no video played

How it works:
  index.hhh returns JSON:
    {"action":"show","content":"<script>document.write(decodeURIComponent(window.atob('BASE64')));</script>"}
  The BASE64 decodes to a URL-encoded HTML ad page containing:
    var reward_currency = 'tokens';
    var strRewardUrl    = 'https://a314.gameloft.com/un/reward.php?csr=t&sid=...';
    function saveReward() { ... }  (from html5VideoPlayer-3.0.js)
  This addon:
    1. Decodes the base64 HTML
    2. Injects a <script> before </body> that fires the reward immediately
    3. Re-encodes and returns the patched response

Notes:
  - reward_currency is set by Gameloft's ad server based on the game context.
    Captured value: 'tokens' (premium currency).  Other contexts may yield
    'bananas', 'revive', etc.
  - reward.php (Gameloft's tracking endpoint) has no rate limiting and accepts
    any sid indefinitely — it's pure analytics, not the actual reward grant.
  - The actual in-game reward grant happens when the WKWebView navigates to
    exit:checkreward:tokens:delivered:1 (intercepted by native iOS game code).
"""

import json
import base64
import urllib.parse
import re
from mitmproxy import http, ctx

# ── Injection ─────────────────────────────────────────────────────────────────
# Injected right before </body>.  By this point every synchronous <script> tag
# in the page has already executed, so reward_currency, strRewardUrl and
# saveReward() (from html5VideoPlayer-3.0.js) are all in scope.
BYPASS_JS = """
<script type="text/javascript">
/* ===== MinionRush Ad Bypass ===== */
(function minionBypass() {
    var DELAY_MS = 600; // ms before firing (let player init finish)

    function fireReward() {
        var currency = (typeof reward_currency !== 'undefined' && reward_currency !== '')
                       ? reward_currency : 'tokens';

        // 1. Force internal reward flags so redirect() appends :checkreward:
        try { reward_delivered = 1;       } catch(e) {}
        try { rewarded          = true;   } catch(e) {}
        try { video_completed   = 1;      } catch(e) {}
        try { endVideoRequestWasMade = true; } catch(e) {}

        // 2. Call saveReward() — fires reward.php (Gameloft tracking) and
        //    also triggers glads:checkreward:dummy:delivered:1 internally
        try {
            if (typeof saveReward === 'function') {
                saveReward();
            } else if (typeof strRewardUrl !== 'undefined') {
                // Fallback: fire reward.php directly via Image beacon
                var img = new Image();
                img.src = strRewardUrl
                        + '&campaign_game_location_id='
                        + (typeof campaign_game_location_id !== 'undefined'
                           ? campaign_game_location_id : '0');
            }
        } catch(e) {}

        // 3. Fire videocomplete: — native iOS WKWebView handler grants reward
        try { document.location = 'videocomplete:'; } catch(e) {}

        // 4. After short delay fire exit:checkreward:<currency>:delivered:1
        //    This is the URL scheme the native game reads to confirm reward type
        setTimeout(function() {
            try {
                document.location = 'exit:checkreward:' + currency + ':delivered:1';
            } catch(e) {}
        }, 300);
    }

    // All synchronous scripts above have already run; just delay slightly
    // to let any deferred player.init() calls finish
    setTimeout(fireReward, DELAY_MS);
})();
</script>
"""


class MinionRushBypass:
    """mitmproxy addon that patches Gameloft ad responses."""

    # ── Response hook ──────────────────────────────────────────────────────
    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        path = flow.request.path

        # Only touch Gameloft's ad server endpoint
        if "a314.gameloft.com" not in host:
            return
        if "index.hhh" not in path:
            return

        # Parse JSON envelope
        try:
            data = json.loads(flow.response.text)
        except Exception as e:
            ctx.log.debug(f"[MinRush] non-JSON response from index.hhh: {e}")
            return

        if data.get("action") != "show":
            action = data.get("action", "?")
            ctx.log.debug(f"[MinRush] index.hhh action={action}, skipping")
            return

        content = data.get("content", "")

        # Locate the base64 payload inside window.atob("...")
        m = re.search(r'window\.atob\("([^"]+)"\)', content)
        if not m:
            ctx.log.warn("[MinRush] atob() not found in ad content")
            return

        try:
            b64_original  = m.group(1)
            url_enc_html  = base64.b64decode(b64_original).decode("utf-8")
            html          = urllib.parse.unquote(url_enc_html)

            # Inject our script just before </body>
            if "</body>" in html:
                patched_html = html.replace("</body>", BYPASS_JS + "\n</body>", 1)
            else:
                # Fallback: append at end
                patched_html = html + BYPASS_JS

            # Re-encode: URL-encode → UTF-8 bytes → base64
            new_url_enc = urllib.parse.quote(patched_html, safe="")
            new_b64     = base64.b64encode(new_url_enc.encode("utf-8")).decode("utf-8")

            # Splice new base64 into the content string
            new_content = content[: m.start(1)] + new_b64 + content[m.end(1) :]
            data["content"] = new_content
            flow.response.text = json.dumps(data)

            # ── Logging ──────────────────────────────────────────────────
            location  = flow.request.query.get("location", "?")
            notifyrd  = flow.request.query.get("notifyrd", "0")

            # Extract reward_currency from the raw HTML for the log line
            rc_match = re.search(r"var reward_currency\s*=\s*'([^']*)'", html)
            currency = rc_match.group(1) if rc_match else "?"

            sid_match = re.search(r"reward\.php\?csr=t&sid=([a-f0-9]+)", html)
            sid_short = sid_match.group(1)[:12] + "..." if sid_match else "?"

            ctx.log.info(
                f"[MinRush] BYPASS INJECTED "
                f"| currency={currency} "
                f"| location={location} "
                f"| notifyrd={notifyrd} "
                f"| sid={sid_short}"
            )

        except Exception as e:
            ctx.log.error(f"[MinRush] Injection error: {e}")
            import traceback
            ctx.log.debug(traceback.format_exc())

    # ── Request hook ───────────────────────────────────────────────────────
    def request(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path

        if "reward.php" in path:
            csr      = flow.request.query.get("csr", "?")
            loc      = flow.request.query.get("holistic_loc", "?")
            sid      = flow.request.query.get("sid", "?")[:14] + "..."
            ctx.log.info(
                f"[MinRush] reward.php → csr={csr} | loc={loc} | sid={sid}"
            )

        elif "track.php" in path:
            event = flow.request.query.get("event_type", "?")
            if "END_VIDEO" in event or "COMPLETE" in event:
                ctx.log.info(f"[MinRush] track.php event={event}")


addons = [MinionRushBypass()]

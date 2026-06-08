from __future__ import annotations

import re
from collections import defaultdict

from fastapi import Depends,  APIRouter

from api.auth import get_current_user, AUTH_DISABLED

from state.shared import ProxyState

router = APIRouter(prefix="/api/scanner", tags=["scanner"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()

# ── Sensitive Data Patterns ────────────────────────────────

SENSITIVE_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)["\s:=]+([A-Za-z0-9/+=]{40})',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "GCP Service Account": r'"type"\s*:\s*"service_account"',
    "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Publishable": r'pk_live_[0-9a-zA-Z]{24,}',
    "Slack Token": r'xox[bpors]-[0-9a-zA-Z]{10,}',
    "Slack Webhook": r'hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}',
    "GitHub Token": r'gh[ps]_[A-Za-z0-9_]{36,}',
    "GitHub Classic Token": r'github_pat_[A-Za-z0-9_]{82}',
    "JWT": r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Bearer Token": r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    "Basic Auth": r'Basic\s+[A-Za-z0-9+/]{8,}={0,2}',
    "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "Password Field": r'(?:password|passwd|pwd|secret|token)["\s:=]+["\']([^"\']{4,})["\']',
    "Internal IP": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "Phone Number": r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b',
    "Credit Card (Visa)": r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "Credit Card (MC)": r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "Stack Trace (Python)": r'Traceback \(most recent call last\)',
    "Stack Trace (Java)": r'at [a-zA-Z0-9$.]+\([A-Za-z0-9]+\.java:\d+\)',
    "Stack Trace (Node)": r'at [A-Za-z0-9_.]+ \([^)]+\.js:\d+:\d+\)',
    "Stack Trace (.NET)": r'at [A-Za-z0-9_.]+\.[A-Za-z0-9_]+\([^)]*\) in [^\n]+:\w+ \d+',
    "SQL Error": r'(?:mysql_fetch|pg_query|sqlite3\.|ORA-\d{5}|SQL syntax|SQLSTATE)',
    "Debug Page": r'(?:Werkzeug Debugger|Laravel|Django Debug|Express error|Symfony Exception)',
    "Directory Listing": r'(?:Index of /|Parent Directory|Directory listing for)',
    "Server Path": r'(?:/var/www/|/home/\w+/|/opt/|/usr/local/|C:\\\\(?:Users|inetpub|Program Files))',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "S3 Bucket": r'(?:https?://)?[a-zA-Z0-9.-]+\.s3(?:\.[a-zA-Z0-9-]+)?\.amazonaws\.com',
    "Heroku API Key": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "SendGrid API Key": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    "Twilio API Key": r'SK[0-9a-fA-F]{32}',
    "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
}

SEVERITY_MAP = {
    "AWS Access Key": "critical", "AWS Secret Key": "critical",
    "Google API Key": "high", "GCP Service Account": "critical",
    "Stripe Secret Key": "critical", "Stripe Publishable": "medium",
    "Slack Token": "high", "GitHub Token": "high", "GitHub Classic Token": "high",
    "Private Key": "critical", "Password Field": "high",
    "JWT": "info", "Bearer Token": "info", "Basic Auth": "medium",
    "Internal IP": "medium", "Email Address": "low", "Phone Number": "medium",
    "SSN": "critical", "Credit Card (Visa)": "critical", "Credit Card (MC)": "critical",
    "Stack Trace (Python)": "medium", "Stack Trace (Java)": "medium",
    "Stack Trace (Node)": "medium", "Stack Trace (.NET)": "medium",
    "SQL Error": "high", "Debug Page": "high", "Directory Listing": "medium",
    "Server Path": "medium", "Firebase URL": "medium", "S3 Bucket": "medium",
    "SendGrid API Key": "critical", "Twilio API Key": "critical", "Mailgun API Key": "critical",
    "Heroku API Key": "medium", "Google OAuth": "medium", "Slack Webhook": "high",
}


@router.post("/sensitive")
def scan_sensitive(data: dict = {}):
    """Scan traffic for sensitive data leaks."""
    flow_id = data.get("flow_id", "")
    max_flows = min(data.get("max_flows", 500), 2000)

    if flow_id:
        flow = state.get_flow(flow_id)
        flows = [flow] if flow else []
    else:
        flows = state.get_flows(limit=max_flows)

    findings = []
    for flow in flows:
        texts_to_scan = [
            ("response_body", flow.response_body or ""),
            ("response_headers", str(flow.response_headers or {})),
            ("request_body", flow.request_body or ""),
            ("request_headers", str(flow.request_headers or {})),
            ("url", flow.url or ""),
        ]

        for location, text in texts_to_scan:
            if not text or len(text) > 1_000_000:
                continue
            for name, pattern in SENSITIVE_PATTERNS.items():
                try:
                    matches = list(re.finditer(pattern, text, re.IGNORECASE))
                    for m in matches[:5]:  # Max 5 matches per pattern per location
                        matched_text = m.group(0)
                        # Mask sensitive values
                        if len(matched_text) > 12:
                            masked = matched_text[:6] + "..." + matched_text[-4:]
                        else:
                            masked = matched_text[:4] + "..."

                        findings.append({
                            "flow_id": flow.id,
                            "host": flow.host,
                            "path": flow.path,
                            "method": flow.method,
                            "pattern_name": name,
                            "severity": SEVERITY_MAP.get(name, "info"),
                            "location": location,
                            "matched": masked,
                            "position": m.start(),
                        })
                except re.error:
                    continue

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    # Summary stats
    by_severity = defaultdict(int)
    by_pattern = defaultdict(int)
    for f in findings:
        by_severity[f["severity"]] += 1
        by_pattern[f["pattern_name"]] += 1

    return {
        "findings": findings[:500],
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_pattern": dict(by_pattern),
    }


# ── Header Security Auditor ───────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "high",
        "desc": "Prevents downgrade attacks and cookie hijacking",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "high",
        "desc": "Prevents XSS and data injection attacks",
        "recommendation": "Add CSP with restrictive default-src",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "desc": "Prevents clickjacking attacks",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "desc": "Prevents MIME-type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "desc": "Legacy XSS filter (modern browsers use CSP)",
        "recommendation": "Add: X-XSS-Protection: 0 (or rely on CSP)",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "medium",
        "desc": "Controls referrer information leakage",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "medium",
        "desc": "Controls browser feature access",
        "recommendation": "Add Permissions-Policy restricting camera, microphone, geolocation",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "low",
        "desc": "Isolates browsing context",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "low",
        "desc": "Prevents cross-origin reads",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}

COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]


@router.post("/headers")
def audit_headers(data: dict = {}):
    """Audit response security headers per domain."""
    target_domain = data.get("domain", "")
    flows = state.get_flows(limit=2000)

    domain_audit: dict[str, dict] = {}

    for flow in flows:
        if target_domain and target_domain not in flow.host:
            continue
        if not flow.response_headers:
            continue
        # Only check text-like responses (most relevant for security headers).
        # An empty content-type is allowed through; a non-empty, non-text one is
        # skipped. (The old "" entry made `"" in ct` always true → audited
        # everything, defeating the filter.)
        ct = flow.response_content_type or ""
        if ct and not any(t in ct for t in ("text/html", "application/json", "application/xml")):
            continue

        domain = flow.host
        if domain not in domain_audit:
            domain_audit[domain] = {
                "domain": domain,
                "missing_headers": [],
                "present_headers": [],
                "cookie_issues": [],
                "score": 0,
                "max_score": 0,
                "grade": "",
                "checked": False,
            }

        audit = domain_audit[domain]
        if audit["checked"]:
            continue
        audit["checked"] = True

        resp_lower = {k.lower(): v for k, v in flow.response_headers.items()}
        score = 0
        max_score = 0
        severity_weight = {"high": 3, "medium": 2, "low": 1}

        for header_key, info in SECURITY_HEADERS.items():
            weight = severity_weight.get(info["severity"], 1)
            max_score += weight
            if header_key in resp_lower:
                score += weight
                audit["present_headers"].append({
                    "name": info["name"],
                    "value": resp_lower[header_key],
                    "severity": info["severity"],
                })
            else:
                audit["missing_headers"].append({
                    "name": info["name"],
                    "severity": info["severity"],
                    "desc": info["desc"],
                    "recommendation": info["recommendation"],
                })

        # Check cookies
        for k, v in flow.response_headers.items():
            if k.lower() == "set-cookie":
                cookie_name = v.split("=")[0].strip()
                missing_flags = []
                v_lower = v.lower()
                for flag in COOKIE_FLAGS:
                    if flag.lower() not in v_lower:
                        missing_flags.append(flag)
                if missing_flags:
                    audit["cookie_issues"].append({
                        "cookie": cookie_name,
                        "missing_flags": missing_flags,
                    })

        # Server info disclosure
        if "server" in resp_lower and len(resp_lower["server"]) > 1:
            audit.setdefault("info_disclosure", [])
            audit["info_disclosure"].append({"header": "Server", "value": resp_lower["server"]})
        if "x-powered-by" in resp_lower:
            audit.setdefault("info_disclosure", [])
            audit["info_disclosure"].append({"header": "X-Powered-By", "value": resp_lower["x-powered-by"]})

        audit["score"] = score
        audit["max_score"] = max_score
        pct = (score / max_score * 100) if max_score > 0 else 0
        if pct >= 80:
            audit["grade"] = "A"
        elif pct >= 60:
            audit["grade"] = "B"
        elif pct >= 40:
            audit["grade"] = "C"
        elif pct >= 20:
            audit["grade"] = "D"
        else:
            audit["grade"] = "F"

    results = sorted(domain_audit.values(), key=lambda x: x["score"])
    for r in results:
        del r["checked"]
    return {"domains": results, "count": len(results)}


# ── Error Fingerprinter ───────────────────────────────────

ERROR_PATTERNS = [
    ("Python/Django", r'(?:Traceback|File "[^"]+\.py", line \d+|django\.)', "Python stack trace detected"),
    ("Python/Flask", r'(?:werkzeug|flask\.app|jinja2\.)', "Flask/Werkzeug error detected"),
    ("Java", r'(?:java\.\w+\.[\w.]+Exception|at \w+\.\w+\(\w+\.java:\d+\))', "Java stack trace detected"),
    ("Node.js", r'(?:at \w+ \([^)]+\.js:\d+:\d+\)|ReferenceError|TypeError:)', "Node.js error detected"),
    (".NET", r'(?:System\.\w+Exception|ASP\.NET|__doPostBack)', ".NET error detected"),
    ("PHP", r'(?:Fatal error:|Parse error:|Warning:.*\bon line\b|<b>(?:Notice|Warning)</b>)', "PHP error detected"),
    ("Ruby", r'(?:ActionController|ActiveRecord|NoMethodError|RuntimeError)', "Ruby error detected"),
    ("SQL", r'(?:mysql_|pg_query|ORA-\d{5}|SQLSTATE|sql syntax|sqlite3\.)', "SQL error leaked"),
    ("Debug Page", r'(?:Werkzeug Debugger|Interactive Console|Debug Mode|DJANGO_SETTINGS_MODULE)', "Debug page exposed"),
    ("Path Disclosure", r'(?:/var/www/|/home/\w+/|/opt/\w+|C:\\\\)', "Server file path leaked"),
    ("Version", r'(?:PHP/\d|Apache/\d|nginx/\d|Express/\d|Tomcat/\d)', "Software version leaked"),
]


@router.get("/errors")
def analyze_errors():
    """Analyze error responses for information leakage."""
    flows = state.get_flows(limit=3000)

    errors = []
    clusters: dict[str, list] = defaultdict(list)

    for flow in flows:
        if flow.status_code < 400:
            continue

        body = flow.response_body or ""
        detected = []

        for tech, pattern, desc in ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                detected.append({"tech": tech, "desc": desc})

        entry = {
            "flow_id": flow.id,
            "host": flow.host,
            "path": flow.path,
            "method": flow.method,
            "status_code": flow.status_code,
            "reason": flow.reason,
            "detected": detected,
            "body_preview": body[:500] if body else "",
            "response_size": len(body),
        }
        errors.append(entry)

        cluster_key = f"{flow.status_code}|{flow.host}"
        clusters[cluster_key].append(entry)

    # Build cluster summary
    cluster_summary = []
    for key, entries in clusters.items():
        status, host = key.split("|", 1)
        all_tech = set()
        for e in entries:
            for d in e["detected"]:
                all_tech.add(d["tech"])
        cluster_summary.append({
            "status_code": int(status),
            "host": host,
            "count": len(entries),
            "technologies": sorted(all_tech),
            "paths": list(set(e["path"] for e in entries))[:10],
        })

    cluster_summary.sort(key=lambda x: x["count"], reverse=True)

    return {
        "errors": errors[:200],
        "total": len(errors),
        "clusters": cluster_summary,
    }
"""
Unified Issues dashboard for pRoxy.

Aggregates findings already produced by the scanner, recon, and
threat_detection routes into one prioritized, normalized view. This module adds
NO new detection logic — it calls the existing finder functions directly (they
are plain Python functions reading from the shared ProxyState) and normalizes
their heterogeneous outputs onto a common 5-level severity scale.

Reused finders:
  scanner.scan_sensitive   -> sensitive-data leaks (severity already 5-level)
  scanner.audit_headers    -> missing security headers per domain
  scanner.analyze_errors   -> error-response information leakage
  recon.fingerprint        -> technology fingerprint disclosure (informational)
  threat_detection.detect_threats -> attack-pattern alerts (low/med/high/crit)
"""
from __future__ import annotations

from collections import defaultdict

from fastapi import Depends, APIRouter

from api.auth import get_current_user, AUTH_DISABLED
from api.routes import scanner, recon, threat_detection
from state.shared import ProxyState

router = APIRouter(
    prefix="/api/issues",
    tags=["issues"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else [],
)
state = ProxyState()

# Canonical 5-level severity scale, highest first.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm_severity(value: str | None) -> str:
    """Map an arbitrary source severity/grade onto the 5-level scale."""
    if not value:
        return "info"
    v = str(value).strip().lower()
    if v in SEVERITY_ORDER:
        return v
    return "info"


def _collect_sensitive(domain: str) -> list[dict]:
    """scanner.scan_sensitive — sensitive-data leaks (body-dict handler)."""
    result = scanner.scan_sensitive({})
    issues = []
    for f in result.get("findings", []):
        host = f.get("host", "")
        if domain and domain not in host:
            continue
        path = f.get("path", "")
        location = f"{host}{path}".strip() or host or f.get("location", "")
        issues.append({
            "source": "scanner",
            "severity": _norm_severity(f.get("severity")),
            "title": f"Sensitive data: {f.get('pattern_name', 'unknown')}",
            "detail": f"Matched {f.get('matched', '')} in {f.get('location', '')} "
                      f"({f.get('method', '')} {host}{path})".strip(),
            "location": location,
        })
    return issues


def _collect_headers(domain: str) -> list[dict]:
    """scanner.audit_headers — missing security headers (body-dict handler)."""
    result = scanner.audit_headers({"domain": domain} if domain else {})
    issues = []
    for d in result.get("domains", []):
        host = d.get("domain", "")
        for h in d.get("missing_headers", []):
            issues.append({
                "source": "scanner",
                "severity": _norm_severity(h.get("severity")),
                "title": f"Missing security header: {h.get('name', 'unknown')}",
                "detail": h.get("desc", "") or h.get("recommendation", ""),
                "location": host,
            })
        for c in d.get("cookie_issues", []):
            issues.append({
                "source": "scanner",
                "severity": "medium",
                "title": f"Insecure cookie: {c.get('cookie', 'unknown')}",
                "detail": f"Missing flags: {', '.join(c.get('missing_flags', []))}",
                "location": host,
            })
    return issues


def _collect_errors(domain: str) -> list[dict]:
    """scanner.analyze_errors — error-response info leakage (no args)."""
    result = scanner.analyze_errors()
    issues = []
    for e in result.get("errors", []):
        host = e.get("host", "")
        if domain and domain not in host:
            continue
        detected = e.get("detected", [])
        # Leaked stack traces / tech details are the real finding; a bare error
        # status with no leak is only informational.
        severity = "medium" if detected else "low"
        techs = ", ".join(d.get("tech", "") for d in detected) or "no tech leak"
        path = e.get("path", "")
        issues.append({
            "source": "scanner",
            "severity": severity,
            "title": f"Error response {e.get('status_code', '')}: {techs}",
            "detail": f"{e.get('method', '')} {host}{path} -> "
                      f"{e.get('status_code', '')} {e.get('reason', '')}".strip(),
            "location": f"{host}{path}".strip() or host,
        })
    return issues


def _collect_fingerprint(domain: str) -> list[dict]:
    """recon.fingerprint — technology disclosure (body-dict handler)."""
    result = recon.fingerprint({"domain": domain} if domain else {})
    issues = []
    for host, categories in result.get("domains", {}).items():
        techs = sorted({t for vals in categories.values() for t in vals})
        if not techs:
            continue
        issues.append({
            "source": "recon",
            "severity": "info",
            "title": f"Technology fingerprint: {host}",
            "detail": "Detected technologies: " + ", ".join(techs),
            "location": host,
        })
    return issues


def _collect_threats(domain: str) -> list[dict]:
    """threat_detection.detect_threats — attack-pattern alerts (query args)."""
    result = threat_detection.detect_threats()
    issues = []
    for alert in result.get("alerts", []):
        # ThreatAlert is a pydantic model; normalize to a dict regardless.
        a = alert.model_dump() if hasattr(alert, "model_dump") else dict(alert)
        # Threat alerts are not per-domain; location is the matched category.
        location = a.get("category", "")
        if domain and domain not in location and domain not in a.get("title", ""):
            # No reliable host on alerts — keep them unless a domain filter is
            # set and clearly doesn't relate.
            pass
        issues.append({
            "source": "threat_detection",
            "severity": _norm_severity(a.get("severity")),
            "title": a.get("title", "Threat detected"),
            "detail": a.get("description", ""),
            "location": location,
        })
    return issues


@router.get("")
def list_issues(domain: str = ""):
    """Aggregate, normalize, dedupe, and prioritize findings from all sources."""
    collectors = (
        _collect_sensitive,
        _collect_headers,
        _collect_errors,
        _collect_fingerprint,
        _collect_threats,
    )

    issues: list[dict] = []
    for collect in collectors:
        try:
            issues.extend(collect(domain))
        except Exception:
            # One failing source must not 500 the whole endpoint; collect the
            # rest of what we can.
            continue

    # Dedupe by (source, title, location).
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict] = []
    for issue in issues:
        key = (issue["source"], issue["title"], issue["location"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(issue)

    # Sort by severity (critical first), then source, then title for stability.
    deduped.sort(key=lambda i: (
        SEVERITY_ORDER.get(i["severity"], 5),
        i["source"],
        i["title"],
    ))

    by_severity: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    for issue in deduped:
        by_severity[issue["severity"]] += 1
        by_source[issue["source"]] += 1

    return {
        "issues": deduped,
        "total": len(deduped),
        "by_severity": dict(by_severity),
        "by_source": dict(by_source),
    }

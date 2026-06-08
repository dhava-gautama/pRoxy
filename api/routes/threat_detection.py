"""
Advanced threat detection and attack pattern analysis for pRoxy.
Perfect for identifying security testing patterns and attack signatures.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel

from api.auth import get_current_user, AUTH_DISABLED
from state.models import _reject_redos
from state.shared import ProxyState

MAX_CUSTOM_PATTERNS = 100

router = APIRouter(
    prefix="/api/threat-detection",
    tags=["threat-detection"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


class ThreatAlert(BaseModel):
    """Represents a detected threat or suspicious pattern."""
    id: str
    timestamp: float
    severity: str  # low, medium, high, critical
    category: str  # injection, enumeration, bruteforce, etc.
    title: str
    description: str
    flow_ids: List[str]
    indicators: List[str]
    confidence: float
    mitigation: Optional[str] = None


class AttackPattern(BaseModel):
    """Attack pattern definition for detection."""
    name: str
    category: str
    patterns: List[str]  # regex patterns
    threshold: int  # how many occurrences trigger alert
    timeframe: int  # time window in seconds
    severity: str


# ── Pre-defined Attack Patterns ──────────────────────────────────

ATTACK_PATTERNS = [
    # SQL Injection Patterns
    AttackPattern(
        name="SQL Injection - Union Based",
        category="injection",
        patterns=[
            r"(?i)\bunion\b.*?\bselect\b",
            r"(?i)\bor\b\s+1\s*=\s*1",
            r"(?i)\bselect\b.*?\bfrom\b.*?\binformation_schema\b",
            r"(?i)'\s*or\s*'1'\s*=\s*'1"
        ],
        threshold=3,
        timeframe=300,
        severity="high"
    ),

    # XSS Patterns
    AttackPattern(
        name="Cross-Site Scripting (XSS)",
        category="injection",
        patterns=[
            r"(?i)<script[^>]*>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe[^>]*src",
            r"(?i)alert\s*\(\s*['\"]"
        ],
        threshold=2,
        timeframe=300,
        severity="medium"
    ),

    # Directory Traversal
    AttackPattern(
        name="Directory Traversal",
        category="injection",
        patterns=[
            r"\.\.[\\/]",
            r"(?i)[\\/]etc[\\/]passwd",
            r"(?i)[\\/]windows[\\/]system32",
            r"%2e%2e%2f",
            r"%2e%2e%5c"
        ],
        threshold=2,
        timeframe=180,
        severity="high"
    ),

    # Brute Force Detection
    AttackPattern(
        name="Authentication Brute Force",
        category="bruteforce",
        patterns=[
            r"(?i)\/login",
            r"(?i)\/auth",
            r"(?i)\/signin",
            r"(?i)password=",
            r"(?i)username="
        ],
        threshold=10,
        timeframe=60,
        severity="medium"
    ),

    # Command Injection
    AttackPattern(
        name="Command Injection",
        category="injection",
        patterns=[
            r"(?i);.*?(ls|dir|cat|type|whoami|id)\b",
            r"(?i)\|\s*(ls|dir|cat|type|whoami|id)\b",
            r"(?i)&&.*?(ls|dir|cat|type|whoami|id)\b",
            r"(?i)`.*?(ls|dir|cat|type|whoami|id)\b"
        ],
        threshold=2,
        timeframe=300,
        severity="high"
    ),

    # Enumeration Patterns
    AttackPattern(
        name="Directory/File Enumeration",
        category="enumeration",
        patterns=[
            r"(?i)\/admin",
            r"(?i)\/backup",
            r"(?i)\/config",
            r"(?i)\.env$",
            r"(?i)\.git",
            r"(?i)\/\.well-known",
            r"(?i)\/robots\.txt",
            r"(?i)\/sitemap\.xml"
        ],
        threshold=15,
        timeframe=120,
        severity="low"
    ),

    # API Abuse Patterns
    AttackPattern(
        name="API Rate Limit Testing",
        category="enumeration",
        patterns=[
            r"(?i)\/api\/",
            r"(?i)\/v[0-9]+\/",
            r"(?i)\/rest\/",
            r"(?i)\/graphql"
        ],
        threshold=50,
        timeframe=60,
        severity="medium"
    ),

    # Malicious User Agents
    AttackPattern(
        name="Suspicious User Agents",
        category="reconnaissance",
        patterns=[
            r"(?i)sqlmap",
            r"(?i)nikto",
            r"(?i)nessus",
            r"(?i)burp",
            r"(?i)owasp zap",
            r"(?i)w3af",
            r"(?i)nmap",
            r"(?i)masscan"
        ],
        threshold=1,
        timeframe=300,
        severity="medium"
    )
]

# Number of pre-defined patterns; custom patterns are everything beyond this.
_BUILTIN_PATTERN_COUNT = len(ATTACK_PATTERNS)


# ── Threat Detection Engine ────────────────────────────────────────

@router.get("/scan")
def detect_threats(
    limit: int = 1000,
    time_range: int = Query(3600, description="Time range in seconds to analyze"),
    min_severity: str = Query("low", description="Minimum severity: low, medium, high, critical")
):
    """Scan recent traffic for attack patterns and threats."""
    flows = state.get_flows(limit=limit)
    current_time = time.time()
    cutoff_time = current_time - time_range

    # Filter flows within time range
    recent_flows = [f for f in flows if f.timestamp >= cutoff_time]

    if not recent_flows:
        return {"alerts": [], "summary": {"total": 0, "by_severity": {}, "by_category": {}}}

    alerts = []
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_severity_level = severity_order.get(min_severity, 1)

    # Analyze patterns
    for pattern in ATTACK_PATTERNS:
        pattern_matches = _detect_pattern_occurrences(recent_flows, pattern)

        if len(pattern_matches) >= pattern.threshold:
            # Create alert
            alert = ThreatAlert(
                id=f"threat-{int(time.time() * 1000)}-{pattern.name.lower().replace(' ', '-')}",
                timestamp=current_time,
                severity=pattern.severity,
                category=pattern.category,
                title=pattern.name,
                description=f"Detected {len(pattern_matches)} occurrences of {pattern.name} "
                           f"in the last {pattern.timeframe} seconds. "
                           f"Threshold: {pattern.threshold} occurrences.",
                flow_ids=[match["flow_id"] for match in pattern_matches],
                indicators=[match["matched_content"] for match in pattern_matches[:10]],  # First 10
                confidence=_calculate_threat_confidence(pattern_matches, pattern),
                mitigation=_get_mitigation_advice(pattern.category, pattern.name)
            )

            # Filter by minimum severity
            if severity_order.get(alert.severity, 1) >= min_severity_level:
                alerts.append(alert)

    # Generate summary
    summary = _generate_threat_summary(alerts)

    return {
        "alerts": alerts,
        "summary": summary,
        "scan_info": {
            "flows_analyzed": len(recent_flows),
            "time_range_seconds": time_range,
            "patterns_checked": len(ATTACK_PATTERNS)
        }
    }


@router.get("/patterns")
def get_attack_patterns():
    """Get all available attack patterns for detection."""
    return {
        "patterns": [p.model_dump() for p in ATTACK_PATTERNS],
        "categories": list(set(p.category for p in ATTACK_PATTERNS)),
        "total_patterns": len(ATTACK_PATTERNS)
    }


@router.get("/statistics")
def get_threat_statistics(
    limit: int = 1000,
    time_range: int = Query(86400, description="Time range in seconds (default: 24 hours)")
):
    """Get threat detection statistics and trends."""
    flows = state.get_flows(limit=limit)
    current_time = time.time()
    cutoff_time = current_time - time_range

    recent_flows = [f for f in flows if f.timestamp >= cutoff_time]

    stats = {
        "total_requests": len(recent_flows),
        "suspicious_requests": 0,
        "attack_categories": Counter(),
        "top_attack_sources": Counter(),
        "attack_timeline": [],
        "severity_distribution": Counter(),
        "most_targeted_paths": Counter()
    }

    # Analyze each flow for suspicious patterns
    for flow in recent_flows:
        flow_suspicious = False
        flow_content = f"{flow.url} {flow.request_body or ''} {flow.response_body or ''}"
        flow_content += " ".join(flow.request_headers.values())

        for pattern in ATTACK_PATTERNS:
            for regex in pattern.patterns:
                if re.search(regex, flow_content, re.IGNORECASE):
                    flow_suspicious = True
                    stats["attack_categories"][pattern.category] += 1
                    stats["severity_distribution"][pattern.severity] += 1

                    # Extract potential attack source
                    source_ip = flow.request_headers.get("x-forwarded-for",
                                flow.request_headers.get("x-real-ip", "unknown"))
                    stats["top_attack_sources"][source_ip] += 1

                    # Track targeted paths
                    path = urlparse(flow.url).path
                    stats["most_targeted_paths"][path] += 1
                    break

        if flow_suspicious:
            stats["suspicious_requests"] += 1

    # Create timeline (1-hour buckets)
    timeline_buckets = defaultdict(int)
    for flow in recent_flows:
        bucket = int(flow.timestamp // 3600) * 3600  # Round to hour
        # Check if flow matches any attack pattern
        flow_content = f"{flow.url} {flow.request_body or ''}"
        for pattern in ATTACK_PATTERNS:
            for regex in pattern.patterns:
                if re.search(regex, flow_content, re.IGNORECASE):
                    timeline_buckets[bucket] += 1
                    break

    stats["attack_timeline"] = [
        {"timestamp": bucket, "attacks": count}
        for bucket, count in sorted(timeline_buckets.items())
    ]

    # Convert counters to dicts for JSON serialization
    stats["attack_categories"] = dict(stats["attack_categories"].most_common())
    stats["top_attack_sources"] = dict(stats["top_attack_sources"].most_common(10))
    stats["severity_distribution"] = dict(stats["severity_distribution"])
    stats["most_targeted_paths"] = dict(stats["most_targeted_paths"].most_common(20))

    return stats


@router.post("/custom-pattern")
def add_custom_pattern(pattern: AttackPattern):
    """Add a custom attack pattern for detection."""
    # Cap the number of custom patterns to prevent unbounded growth (DoS).
    if len(ATTACK_PATTERNS) - _BUILTIN_PATTERN_COUNT >= MAX_CUSTOM_PATTERNS:
        raise HTTPException(400, f"Too many custom patterns (max {MAX_CUSTOM_PATTERNS})")

    # Validate regex patterns: must compile and must not be ReDoS-prone, since
    # each pattern is run via re.search against every flow on every scan.
    for regex in pattern.patterns:
        try:
            re.compile(regex)
        except re.error as e:
            raise HTTPException(400, f"Invalid regex pattern '{regex}': {e}")
        try:
            _reject_redos(regex)
        except ValueError as e:
            raise HTTPException(400, f"Dangerous regex pattern '{regex}': {e}")

    # Add to patterns list (in production, this would be persisted)
    ATTACK_PATTERNS.append(pattern)

    return {
        "message": "Custom pattern added successfully",
        "pattern_id": len(ATTACK_PATTERNS) - 1,
        "total_patterns": len(ATTACK_PATTERNS)
    }


# ── Helper Functions ─────────────────────────────────────────────

def _detect_pattern_occurrences(flows: List, pattern: AttackPattern) -> List[Dict]:
    """Detect occurrences of an attack pattern in flows."""
    matches = []
    current_time = time.time()
    pattern_timeframe_cutoff = current_time - pattern.timeframe

    for flow in flows:
        if flow.timestamp < pattern_timeframe_cutoff:
            continue

        # Combine all searchable content
        searchable_content = f"{flow.url} {flow.request_body or ''} {flow.response_body or ''}"
        searchable_content += " ".join(flow.request_headers.values())
        searchable_content += " ".join(flow.response_headers.values())

        for regex in pattern.patterns:
            match = re.search(regex, searchable_content, re.IGNORECASE)
            if match:
                matches.append({
                    "flow_id": flow.id,
                    "timestamp": flow.timestamp,
                    "matched_pattern": regex,
                    "matched_content": match.group(0),
                    "full_url": flow.url,
                    "method": flow.method,
                    "status_code": flow.status_code
                })
                break  # One match per flow per pattern

    return matches


def _calculate_threat_confidence(matches: List[Dict], pattern: AttackPattern) -> float:
    """Calculate confidence score for threat detection."""
    base_confidence = 0.7

    # Increase confidence based on number of occurrences
    occurrence_bonus = min(0.2, len(matches) * 0.02)

    # Increase confidence for high-severity patterns
    severity_bonus = {"low": 0.0, "medium": 0.05, "high": 0.1, "critical": 0.15}.get(
        pattern.severity, 0.0
    )

    # Increase confidence if multiple different patterns match
    unique_patterns = len(set(match["matched_pattern"] for match in matches))
    pattern_bonus = min(0.1, unique_patterns * 0.03)

    return min(1.0, base_confidence + occurrence_bonus + severity_bonus + pattern_bonus)


def _get_mitigation_advice(category: str, pattern_name: str) -> str:
    """Get mitigation advice for detected threats."""
    mitigations = {
        "injection": "Implement input validation, parameterized queries, and output encoding. "
                    "Use a web application firewall (WAF) to filter malicious requests.",
        "bruteforce": "Implement rate limiting, account lockouts, and CAPTCHA. "
                     "Monitor for unusual login patterns and consider IP blocking.",
        "enumeration": "Implement proper access controls and remove unnecessary file exposure. "
                      "Use rate limiting to prevent automated scanning.",
        "reconnaissance": "Monitor and block suspicious user agents. "
                         "Implement request throttling and consider honeypots.",
        "default": "Review the detected pattern and implement appropriate security controls. "
                  "Consider updating your security policies and monitoring."
    }

    return mitigations.get(category, mitigations["default"])


def _generate_threat_summary(alerts: List[ThreatAlert]) -> Dict[str, Any]:
    """Generate summary statistics for threats."""
    if not alerts:
        return {"total": 0, "by_severity": {}, "by_category": {}}

    summary = {
        "total": len(alerts),
        "by_severity": Counter(alert.severity for alert in alerts),
        "by_category": Counter(alert.category for alert in alerts),
        "highest_confidence": max(alert.confidence for alert in alerts),
        "most_recent": max(alert.timestamp for alert in alerts),
        "unique_flows_affected": len(set(flow_id for alert in alerts for flow_id in alert.flow_ids))
    }

    # Convert counters to dicts
    summary["by_severity"] = dict(summary["by_severity"])
    summary["by_category"] = dict(summary["by_category"])

    return summary
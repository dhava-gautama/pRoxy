"""
Advanced traffic analysis and analytics for pRoxy.
Perfect for pentesting, security testing, and traffic analysis.
"""
from __future__ import annotations

import json
import re
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import JSONResponse

from api.auth import get_current_user, AUTH_DISABLED
from state.shared import ProxyState
from state.models import FlowRecord

router = APIRouter(
    prefix="/api/analytics",
    tags=["analytics"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()


# ── Traffic Metrics ────────────────────────────────────────────────

@router.get("/metrics")
def get_traffic_metrics(
    limit: int = 1000,
    time_range: int = Query(3600, description="Time range in seconds (default: 1 hour)")
):
    """Get comprehensive traffic metrics for dashboard."""
    flows = state.get_flows(limit=limit)
    current_time = time.time()
    cutoff_time = current_time - time_range

    # Filter flows within time range
    recent_flows = [f for f in flows if f.timestamp >= cutoff_time]

    if not recent_flows:
        return _empty_metrics()

    # Calculate metrics
    total_requests = len(recent_flows)
    total_responses = len([f for f in recent_flows if f.completed])

    # Separate DNS vs HTTP flows
    dns_flows = [f for f in recent_flows if f.method == "DNS"]
    http_flows = [f for f in recent_flows if f.method != "DNS"]

    total_dns_queries = len(dns_flows)
    total_http_requests = len(http_flows)

    # Status code breakdown
    status_codes = Counter(f.status_code for f in recent_flows if f.status_code > 0)

    # Response time statistics
    response_times = [f.duration_ms for f in recent_flows if f.duration_ms > 0]
    avg_response_time = sum(response_times) / len(response_times) if response_times else 0

    # Traffic by host
    hosts = Counter(f.host for f in recent_flows)

    # Method distribution
    methods = Counter(f.method for f in recent_flows)

    # Content type analysis
    content_types = Counter()
    for flow in recent_flows:
        ct = flow.response_content_type or "unknown"
        # Simplify content types
        if "json" in ct:
            content_types["application/json"] += 1
        elif "html" in ct:
            content_types["text/html"] += 1
        elif "javascript" in ct:
            content_types["application/javascript"] += 1
        elif "css" in ct:
            content_types["text/css"] += 1
        elif "image" in ct:
            content_types["image/*"] += 1
        else:
            content_types[ct.split(";")[0] if ";" in ct else ct] += 1

    # Error rate calculation
    error_requests = len([f for f in recent_flows if f.status_code >= 400])
    error_rate = (error_requests / total_requests * 100) if total_requests > 0 else 0

    # Data transfer statistics
    total_request_size = sum(len(f.request_body or "") for f in recent_flows)
    total_response_size = sum(f.response_size or 0 for f in recent_flows)

    return {
        "time_range": time_range,
        "total_requests": total_requests,
        "total_responses": total_responses,
        "total_dns_queries": total_dns_queries,
        "total_http_requests": total_http_requests,
        "avg_response_time_ms": round(avg_response_time, 2),
        "error_rate_percent": round(error_rate, 2),
        "total_request_size_bytes": total_request_size,
        "total_response_size_bytes": total_response_size,
        "requests_per_minute": round((total_requests / (time_range / 60)), 2),
        "dns_queries_per_minute": round((total_dns_queries / (time_range / 60)), 2),
        "status_codes": dict(status_codes.most_common()),
        "top_hosts": dict(hosts.most_common(10)),
        "methods": dict(methods),
        "content_types": dict(content_types.most_common(10)),
        "dns_method_breakdown": {
            "native_dns": len([f for f in dns_flows if f.dns_method == "native-dns"]),
            "doh": len([f for f in recent_flows if f.dns_method == "doh"]),
            "mapping": len([f for f in recent_flows if f.dns_method == "mapping"])
        }
    }


@router.get("/timeline")
def get_traffic_timeline(
    limit: int = 500,
    interval_minutes: int = Query(5, description="Time interval in minutes for grouping"),
    time_range: int = Query(3600, description="Time range in seconds")
):
    """Get traffic timeline data for charting attack sequences."""
    flows = state.get_flows(limit=limit)
    current_time = time.time()
    cutoff_time = current_time - time_range

    recent_flows = [f for f in flows if f.timestamp >= cutoff_time]

    if not recent_flows:
        return {"timeline": [], "intervals": []}

    # Group flows by time intervals
    interval_seconds = interval_minutes * 60
    timeline = defaultdict(lambda: {
        "timestamp": 0,
        "requests": 0,
        "errors": 0,
        "avg_response_time": 0,
        "unique_hosts": set(),
        "response_sizes": []
    })

    for flow in recent_flows:
        # Calculate interval bucket
        interval_start = int(flow.timestamp // interval_seconds) * interval_seconds

        bucket = timeline[interval_start]
        bucket["timestamp"] = interval_start
        bucket["requests"] += 1
        if flow.status_code >= 400:
            bucket["errors"] += 1
        if flow.duration_ms > 0:
            bucket["response_sizes"].append(flow.duration_ms)
        bucket["unique_hosts"].add(flow.host)

    # Calculate averages and convert to list
    timeline_data = []
    for interval_start in sorted(timeline.keys()):
        bucket = timeline[interval_start]
        avg_time = (
            sum(bucket["response_sizes"]) / len(bucket["response_sizes"])
            if bucket["response_sizes"] else 0
        )

        timeline_data.append({
            "timestamp": interval_start,
            "datetime": datetime.fromtimestamp(interval_start).isoformat(),
            "requests": bucket["requests"],
            "errors": bucket["errors"],
            "error_rate": (bucket["errors"] / bucket["requests"] * 100) if bucket["requests"] > 0 else 0,
            "avg_response_time_ms": round(avg_time, 2),
            "unique_hosts": len(bucket["unique_hosts"])
        })

    return {
        "timeline": timeline_data,
        "interval_minutes": interval_minutes,
        "total_intervals": len(timeline_data)
    }


# ── Content Analysis ────────────────────────────────────────────────

@router.get("/content/analysis")
def analyze_content(
    limit: int = 1000,
    include_sensitive: bool = Query(True, description="Include sensitive data analysis")
):
    """Analyze request/response content for security insights."""
    flows = state.get_flows(limit=limit)

    analysis = {
        "total_flows": len(flows),
        "content_patterns": {},
        "sensitive_data": {},
        "api_endpoints": [],
        "file_types": Counter(),
        "authentication_patterns": {},
        "security_headers": {}
    }

    # Pattern definitions for sensitive data
    sensitive_patterns = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone": r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        "ssn": r'\b\d{3}-?\d{2}-?\d{4}\b',
        "api_key": r'["\']?(?:api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
        "password": r'["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',
        "jwt": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
    }

    # Security headers to check for
    security_headers = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "x-xss-protection"
    ]

    api_paths = set()

    for flow in flows:
        # Analyze URL patterns
        parsed_url = urlparse(flow.url)
        path = parsed_url.path

        # Detect API endpoints
        if any(indicator in path.lower() for indicator in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
            api_paths.add(f"{flow.method} {path}")

        # File type analysis
        if "." in path:
            ext = path.split(".")[-1].lower()
            if len(ext) <= 5:  # Reasonable file extension length
                analysis["file_types"][ext] += 1

        # Analyze request/response content for sensitive patterns
        if include_sensitive:
            combined_content = f"{flow.request_body or ''} {flow.response_body or ''}"

            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, combined_content, re.IGNORECASE)
                if matches:
                    if pattern_name not in analysis["sensitive_data"]:
                        analysis["sensitive_data"][pattern_name] = 0
                    analysis["sensitive_data"][pattern_name] += len(matches)

        # Authentication pattern analysis
        auth_header = flow.request_headers.get("authorization", "").lower()
        if auth_header:
            if auth_header.startswith("bearer"):
                analysis["authentication_patterns"]["bearer_token"] = \
                    analysis["authentication_patterns"].get("bearer_token", 0) + 1
            elif auth_header.startswith("basic"):
                analysis["authentication_patterns"]["basic_auth"] = \
                    analysis["authentication_patterns"].get("basic_auth", 0) + 1
            else:
                analysis["authentication_patterns"]["other"] = \
                    analysis["authentication_patterns"].get("other", 0) + 1

        # Security headers analysis
        for header_name in security_headers:
            if header_name in [h.lower() for h in flow.response_headers.keys()]:
                analysis["security_headers"][header_name] = \
                    analysis["security_headers"].get(header_name, 0) + 1

    # Convert API paths to sorted list
    analysis["api_endpoints"] = sorted(list(api_paths))[:50]  # Top 50 endpoints
    analysis["file_types"] = dict(analysis["file_types"].most_common(20))

    return analysis


@router.get("/content/secrets")
def detect_secrets(limit: int = 1000, context_size: int = Query(50, description="Characters around detected secret")):
    """Detect potential secrets and sensitive information in traffic."""
    flows = state.get_flows(limit=limit)

    # Enhanced secret detection patterns
    secret_patterns = {
        "aws_access_key": r'AKIA[0-9A-Z]{16}',
        "aws_secret_key": r'[A-Za-z0-9/+=]{40}',
        "github_token": r'ghp_[A-Za-z0-9]{36}',
        "slack_token": r'xox[baprs]-[A-Za-z0-9-]+',
        "api_key_generic": r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
        "private_key": r'-----BEGIN[A-Z\s]+PRIVATE KEY-----',
        "password_in_url": r'[?&](?:password|pwd|pass)=([^&\s]+)',
        "jwt_token": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "database_url": r'(?:mysql|postgresql|mongodb)://[^\s/]+:[^\s/@]+@[^\s/]+',
    }

    findings = []

    for flow in flows:
        # Check both request and response content
        contents = [
            ("request_body", flow.request_body or ""),
            ("response_body", flow.response_body or ""),
            ("request_headers", json.dumps(flow.request_headers)),
            ("response_headers", json.dumps(flow.response_headers)),
            ("url", flow.url)
        ]

        for content_type, content in contents:
            if not content:
                continue

            for secret_type, pattern in secret_patterns.items():
                matches = list(re.finditer(pattern, content, re.IGNORECASE))

                for match in matches:
                    start = max(0, match.start() - context_size)
                    end = min(len(content), match.end() + context_size)
                    context = content[start:end]

                    findings.append({
                        "flow_id": flow.id,
                        "flow_url": flow.url,
                        "flow_method": flow.method,
                        "flow_timestamp": flow.timestamp,
                        "secret_type": secret_type,
                        "location": content_type,
                        "matched_text": match.group(0),
                        "context": context,
                        "confidence": _calculate_secret_confidence(secret_type, match.group(0))
                    })

    # Sort by confidence score (highest first)
    findings.sort(key=lambda x: x["confidence"], reverse=True)

    return {
        "total_findings": len(findings),
        "findings": findings[:100],  # Limit to top 100 findings
        "summary": _summarize_secret_findings(findings)
    }


# ── Advanced Filtering ──────────────────────────────────────────────

@router.get("/filter/advanced")
def advanced_filter(
    content_type: Optional[str] = None,
    status_code_range: Optional[str] = Query(None, description="e.g., '400-499' for client errors"),
    response_size_range: Optional[str] = Query(None, description="e.g., '1000-5000' for bytes"),
    duration_range: Optional[str] = Query(None, description="e.g., '100-1000' for milliseconds"),
    contains_headers: Optional[str] = Query(None, description="Comma-separated header names"),
    host_pattern: Optional[str] = None,
    path_pattern: Optional[str] = None,
    method: Optional[str] = None,
    has_sensitive_data: Optional[bool] = None,
    limit: int = 200
):
    """Advanced filtering with multiple criteria for detailed traffic analysis."""
    flows = state.get_flows(limit=limit * 2)  # Get more initially for filtering

    filtered_flows = []

    for flow in flows:
        # Apply filters
        if content_type and content_type.lower() not in (flow.response_content_type or "").lower():
            continue

        if status_code_range and not _in_range(flow.status_code, status_code_range):
            continue

        if response_size_range and not _in_range(flow.response_size or 0, response_size_range):
            continue

        if duration_range and not _in_range(flow.duration_ms or 0, duration_range):
            continue

        if contains_headers:
            header_names = [h.strip().lower() for h in contains_headers.split(",")]
            flow_headers = [h.lower() for h in flow.response_headers.keys()]
            if not any(header in flow_headers for header in header_names):
                continue

        if host_pattern and not re.search(host_pattern, flow.host, re.IGNORECASE):
            continue

        if path_pattern and not re.search(path_pattern, urlparse(flow.url).path, re.IGNORECASE):
            continue

        if method and flow.method.upper() != method.upper():
            continue

        if has_sensitive_data is not None:
            content = f"{flow.request_body or ''} {flow.response_body or ''}"
            has_secrets = bool(re.search(r'(?:password|token|key|secret|api)', content, re.IGNORECASE))
            if has_sensitive_data != has_secrets:
                continue

        filtered_flows.append(flow)

        if len(filtered_flows) >= limit:
            break

    return {
        "total_matches": len(filtered_flows),
        "flows": filtered_flows,
        "applied_filters": {
            "content_type": content_type,
            "status_code_range": status_code_range,
            "response_size_range": response_size_range,
            "duration_range": duration_range,
            "contains_headers": contains_headers,
            "host_pattern": host_pattern,
            "path_pattern": path_pattern,
            "method": method,
            "has_sensitive_data": has_sensitive_data
        }
    }


# ── Advanced Analytics ───────────────────────────────────────────────

@router.get("/advanced")
def get_advanced_analytics(limit: int = 1000):
    """Get comprehensive flow and connection analytics with detailed insights."""
    # Get the addon instance from the state
    if not state.proxy_addon:
        return {"error": "ProxyAddon not initialized", "analytics": {}}

    try:
        # Get comprehensive analytics from the enhanced addon
        analytics = state.proxy_addon.get_traffic_analytics()

        # Add summary statistics
        analytics["summary"] = {
            "total_connection_patterns": len(state.proxy_addon._connection_patterns) if hasattr(state.proxy_addon, '_connection_patterns') else 0,
            "total_flows_analyzed": len(state._flows),
            "analysis_timestamp": time.time(),
            "features_enabled": {
                "connection_analysis": True,
                "flow_lifecycle_tracking": True,
                "tls_security_analysis": True,
                "performance_monitoring": True
            }
        }

        return analytics
    except Exception as e:
        return {
            "error": f"Failed to generate advanced analytics: {str(e)}",
            "analytics": {},
            "fallback_data": {
                "total_flows": len(state._flows),
                "basic_metrics_available": True
            }
        }


@router.get("/connection-patterns")
def get_connection_patterns():
    """Get detailed connection pattern analysis."""
    if not state.proxy_addon:
        return {"error": "ProxyAddon not initialized"}

    try:
        return state.proxy_addon.get_connection_analytics()
    except Exception as e:
        return {"error": f"Failed to get connection analytics: {str(e)}"}


@router.get("/flow-lifecycle")
def get_flow_lifecycle():
    """Get flow lifecycle statistics and patterns."""
    if not state.proxy_addon:
        return {"error": "ProxyAddon not initialized"}

    try:
        return state.proxy_addon.get_flow_lifecycle_stats()
    except Exception as e:
        return {"error": f"Failed to get flow lifecycle stats: {str(e)}"}


@router.get("/tls-security")
def get_tls_security():
    """Get comprehensive TLS security analysis."""
    if not state.proxy_addon:
        return {"error": "ProxyAddon not initialized"}

    try:
        return state.proxy_addon.get_tls_security_analysis()
    except Exception as e:
        return {"error": f"Failed to get TLS security analysis: {str(e)}"}


# ── Export & Reporting ───────────────────────────────────────────────

@router.get("/export/summary")
def export_analysis_summary(
    format: str = Query("json", description="Export format: json, csv, html"),
    limit: int = 1000
):
    """Export comprehensive traffic analysis summary."""
    # Get all analysis data
    metrics = get_traffic_metrics(limit=limit)
    content_analysis = analyze_content(limit=limit)
    secrets = detect_secrets(limit=limit)

    summary = {
        "generated_at": datetime.now().isoformat(),
        "analysis_period": f"{limit} most recent flows",
        "traffic_metrics": metrics,
        "content_analysis": content_analysis,
        "security_findings": {
            "total_secrets_found": secrets["total_findings"],
            "secret_types": secrets["summary"],
            "high_confidence_findings": len([
                f for f in secrets["findings"]
                if f["confidence"] >= 0.8
            ])
        },
        "recommendations": _generate_recommendations(metrics, content_analysis, secrets)
    }

    if format == "json":
        return JSONResponse(
            content=summary,
            headers={"Content-Disposition": "attachment; filename=traffic_analysis.json"}
        )
    elif format == "html":
        html_content = _generate_html_report(summary)
        return JSONResponse(
            content={"html": html_content},
            headers={"Content-Disposition": "attachment; filename=traffic_analysis.html"}
        )
    else:
        raise HTTPException(400, "Unsupported format. Use: json, html")


# ── Helper Functions ─────────────────────────────────────────────────

def _empty_metrics():
    """Return empty metrics structure."""
    return {
        "time_range": 0,
        "total_requests": 0,
        "total_responses": 0,
        "avg_response_time_ms": 0,
        "error_rate_percent": 0,
        "total_request_size_bytes": 0,
        "total_response_size_bytes": 0,
        "requests_per_minute": 0,
        "status_codes": {},
        "top_hosts": {},
        "methods": {},
        "content_types": {}
    }


def _calculate_secret_confidence(secret_type: str, matched_text: str) -> float:
    """Calculate confidence score for detected secrets."""
    confidence = 0.5  # Base confidence

    # Type-specific confidence adjustments
    if secret_type in ["aws_access_key", "github_token", "slack_token"]:
        confidence = 0.9  # High confidence for well-defined patterns
    elif secret_type == "jwt_token" and matched_text.count(".") == 2:
        confidence = 0.8  # JWT tokens are well-structured
    elif secret_type == "private_key":
        confidence = 0.95  # Private key headers are very distinctive
    elif "generic" in secret_type:
        confidence = 0.6  # Generic patterns are less reliable

    # Length-based confidence adjustment
    if len(matched_text) >= 40:
        confidence += 0.1
    elif len(matched_text) < 10:
        confidence -= 0.2

    return max(0.1, min(1.0, confidence))


def _summarize_secret_findings(findings: List[Dict]) -> Dict:
    """Summarize secret findings by type."""
    summary = Counter()
    high_confidence = 0

    for finding in findings:
        summary[finding["secret_type"]] += 1
        if finding["confidence"] >= 0.8:
            high_confidence += 1

    return {
        "by_type": dict(summary),
        "high_confidence_count": high_confidence,
        "unique_types": len(summary)
    }


def _in_range(value: int, range_str: str) -> bool:
    """Check if value is within specified range (e.g., '100-500')."""
    try:
        if "-" not in range_str:
            return value == int(range_str)
        min_val, max_val = map(int, range_str.split("-", 1))
        return min_val <= value <= max_val
    except ValueError:
        return True  # Invalid range, don't filter


def _generate_recommendations(metrics: Dict, content_analysis: Dict, secrets: Dict) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []

    # Error rate recommendations
    if metrics["error_rate_percent"] > 10:
        recommendations.append(
            f"High error rate detected ({metrics['error_rate_percent']:.1f}%). "
            "Review failed requests for potential security issues."
        )

    # Sensitive data recommendations
    if secrets["total_findings"] > 0:
        recommendations.append(
            f"Found {secrets['total_findings']} potential secrets in traffic. "
            "Review and secure sensitive data transmission."
        )

    # Security headers recommendations
    security_headers = content_analysis.get("security_headers", {})
    missing_headers = []
    expected_headers = ["strict-transport-security", "content-security-policy", "x-frame-options"]

    for header in expected_headers:
        if header not in security_headers or security_headers[header] == 0:
            missing_headers.append(header)

    if missing_headers:
        recommendations.append(
            f"Missing security headers: {', '.join(missing_headers)}. "
            "Consider implementing these headers for better security."
        )

    # API endpoint recommendations
    api_count = len(content_analysis.get("api_endpoints", []))
    if api_count > 20:
        recommendations.append(
            f"Detected {api_count} API endpoints. "
            "Consider implementing rate limiting and authentication."
        )

    if not recommendations:
        recommendations.append("No major security issues detected in current traffic analysis.")

    return recommendations


def _generate_html_report(summary: Dict) -> str:
    """Generate HTML report from analysis summary."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>pRoxy Traffic Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ color: #333; border-bottom: 2px solid #007acc; }}
            .section {{ margin: 20px 0; }}
            .metric {{ background: #f5f5f5; padding: 10px; margin: 5px 0; }}
            .recommendation {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }}
            .finding {{ background: #f8d7da; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1 class="header">pRoxy Traffic Analysis Report</h1>
        <p><strong>Generated:</strong> {summary['generated_at']}</p>
        <p><strong>Analysis Period:</strong> {summary['analysis_period']}</p>

        <div class="section">
            <h2>Traffic Metrics</h2>
            <div class="metric">Total Requests: {summary['traffic_metrics']['total_requests']}</div>
            <div class="metric">Error Rate: {summary['traffic_metrics']['error_rate_percent']:.1f}%</div>
            <div class="metric">Avg Response Time: {summary['traffic_metrics']['avg_response_time_ms']:.1f}ms</div>
        </div>

        <div class="section">
            <h2>Security Findings</h2>
            <div class="finding">Secrets Found: {summary['security_findings']['total_secrets_found']}</div>
            <div class="finding">High Confidence: {summary['security_findings']['high_confidence_findings']}</div>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            {''.join(f'<div class="recommendation">{rec}</div>' for rec in summary['recommendations'])}
        </div>
    </body>
    </html>
    """
    return html
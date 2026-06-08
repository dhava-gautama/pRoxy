from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict

import httpx
from fastapi import Depends,  APIRouter, HTTPException

from api.auth import get_current_user, AUTH_DISABLED

from state.shared import ProxyState

router = APIRouter(prefix="/api/recon", tags=["recon"],
    dependencies=[Depends(get_current_user)] if not AUTH_DISABLED else []
)
state = ProxyState()

# ── Technology Fingerprinting ──────────────────────────────

TECH_SIGNATURES = {
    "headers": {
        "Server": {
            "nginx": "Nginx",
            "apache": "Apache",
            "cloudflare": "Cloudflare",
            "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn",
            "microsoft-iis": "Microsoft IIS",
            "openresty": "OpenResty",
            "litespeed": "LiteSpeed",
            "caddy": "Caddy",
            "cowboy": "Cowboy (Erlang)",
            "kestrel": "Kestrel (.NET)",
            "jetty": "Jetty (Java)",
            "tomcat": "Apache Tomcat",
            "werkzeug": "Werkzeug (Python)",
            "tornado": "Tornado (Python)",
            "express": "Express.js",
            "envoy": "Envoy Proxy",
        },
        "X-Powered-By": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "flask": "Flask",
            "django": "Django",
            "ruby": "Ruby",
            "servlet": "Java Servlet",
            "wp engine": "WP Engine (WordPress)",
            "craft cms": "Craft CMS",
            "drupal": "Drupal",
        },
        "X-Generator": {
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "ghost": "Ghost CMS",
            "hugo": "Hugo",
            "gatsby": "Gatsby",
            "jekyll": "Jekyll",
        },
        "Via": {
            "cloudfront": "AWS CloudFront",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "varnish": "Varnish Cache",
            "squid": "Squid Proxy",
        },
        "X-Cache": {
            "cloudfront": "AWS CloudFront",
            "fastly": "Fastly",
            "varnish": "Varnish",
        },
    },
    "cookie_patterns": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java (Servlet/Spring)",
        "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "_rails_session": "Ruby on Rails",
        "connect.sid": "Express.js (connect)",
        "wp-settings": "WordPress",
        "__cf_bm": "Cloudflare Bot Management",
        "incap_ses": "Imperva/Incapsula",
    },
    "body_patterns": [
        (r"wp-content/|wp-includes/|wp-json/", "WordPress"),
        (r"sites/default/files|drupal\.js|Drupal\.settings", "Drupal"),
        (r"/__next/|_next/static|_next/data", "Next.js"),
        (r"/_nuxt/|__nuxt", "Nuxt.js"),
        (r"react|reactDOM|__REACT", "React"),
        (r"ng-version|angular\.js|ng-app", "Angular"),
        (r"vue\.js|__vue__|v-cloak", "Vue.js"),
        (r"jquery|jQuery", "jQuery"),
        (r"bootstrap\.min\.(js|css)", "Bootstrap"),
        (r"tailwindcss|tailwind\.css", "Tailwind CSS"),
        (r"swagger-ui|openapi|swagger\.json", "Swagger/OpenAPI"),
        (r"graphql|__schema|GraphQL", "GraphQL"),
        (r"firebase|firebaseapp", "Firebase"),
        (r"cdn\.shopify\.com|Shopify\.", "Shopify"),
        (r"wix\.com|wixstatic", "Wix"),
        (r"squarespace\.com|squarespace-cdn", "Squarespace"),
    ],
    "header_presence": {
        "X-Drupal-Cache": "Drupal",
        "X-Drupal-Dynamic-Cache": "Drupal",
        "X-WordPress-*": "WordPress",
        "X-Shopify-Stage": "Shopify",
        "X-Amz-Cf-Id": "AWS CloudFront",
        "X-Amz-Request-Id": "AWS",
        "X-Azure-Ref": "Azure",
        "X-Vercel-Id": "Vercel",
        "X-Netlify-*": "Netlify",
        "CF-RAY": "Cloudflare",
        "X-Fastly-Request-ID": "Fastly",
        "X-GitHub-Request-Id": "GitHub",
        "X-AspNet-Version": "ASP.NET",
        "X-AspNetMvc-Version": "ASP.NET MVC",
        "X-Django-*": "Django",
        "X-Runtime": "Ruby on Rails",
        "X-Request-Id": "Rails/Phoenix",
    },
}


@router.post("/fingerprint")
def fingerprint(data: dict):
    """Analyze traffic to fingerprint technologies per domain."""
    target_domain = data.get("domain", "")
    flows = state.get_flows(limit=2000)

    domain_tech: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for flow in flows:
        if target_domain and target_domain not in flow.host:
            continue

        domain = flow.host
        resp_headers = flow.response_headers or {}

        # Check header values
        for header_name, sigs in TECH_SIGNATURES["headers"].items():
            for h_key, h_val in resp_headers.items():
                if h_key.lower() == header_name.lower():
                    for pattern, tech in sigs.items():
                        if pattern.lower() in h_val.lower():
                            domain_tech[domain]["Server/Infra"].add(tech)
                            # Also store raw value
                            domain_tech[domain]["_raw_" + header_name].add(h_val)

        # Check header presence
        for h_pattern, tech in TECH_SIGNATURES["header_presence"].items():
            if h_pattern.endswith("*"):
                prefix = h_pattern[:-1].lower()
                for h_key in resp_headers:
                    if h_key.lower().startswith(prefix):
                        domain_tech[domain]["Infrastructure"].add(tech)
            else:
                for h_key in resp_headers:
                    if h_key.lower() == h_pattern.lower():
                        domain_tech[domain]["Infrastructure"].add(tech)

        # Check cookies
        set_cookie = ""
        for h_key, h_val in resp_headers.items():
            if h_key.lower() == "set-cookie":
                set_cookie += h_val + ";"
        for cookie_name, tech in TECH_SIGNATURES["cookie_patterns"].items():
            if cookie_name.lower() in set_cookie.lower():
                domain_tech[domain]["Framework"].add(tech)

        # Check response body patterns
        body = flow.response_body or ""
        if body and len(body) < 500_000:
            for pattern, tech in TECH_SIGNATURES["body_patterns"]:
                if re.search(pattern, body, re.IGNORECASE):
                    domain_tech[domain]["Frontend/CMS"].add(tech)

        # Check Content-Type hints
        ct = (resp_headers.get("content-type") or resp_headers.get("Content-Type") or "").lower()
        if "application/graphql" in ct or "graphql" in flow.path.lower():
            domain_tech[domain]["API"].add("GraphQL")
        if "application/grpc" in ct:
            domain_tech[domain]["API"].add("gRPC")

    # Build result
    result = {}
    for domain, categories in domain_tech.items():
        result[domain] = {
            cat: sorted(techs)
            for cat, techs in categories.items()
            if not cat.startswith("_raw_")
        }
    return {"domains": result, "count": len(result)}


# ── Subdomain Collector ────────────────────────────────────

@router.get("/subdomains")
def collect_subdomains(domain: str = ""):
    """Passively collect subdomains from all captured traffic."""
    flows = state.get_flows(limit=5000)
    subdomains: set[str] = set()

    for flow in flows:
        # Host header
        _add_domain(subdomains, flow.host, domain)

        resp_headers = flow.response_headers or {}

        for _, v in resp_headers.items():
            _extract_domains_from_text(subdomains, v, domain)

        # Response body
        body = flow.response_body or ""
        if body and len(body) < 500_000:
            _extract_domains_from_text(subdomains, body, domain)

        # Request body (for APIs that reference other services)
        req_body = flow.request_body or ""
        if req_body and len(req_body) < 100_000:
            _extract_domains_from_text(subdomains, req_body, domain)

    return {"subdomains": sorted(subdomains), "count": len(subdomains)}


def _add_domain(result: set, hostname: str, base_domain: str):
    if not hostname:
        return
    hostname = hostname.split(":")[0].lower().strip()
    if base_domain:
        if hostname.endswith(base_domain.lower()):
            result.add(hostname)
    else:
        result.add(hostname)


def _extract_domains_from_text(result: set, text: str, base_domain: str):
    # Find domain-like patterns
    pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    for match in re.finditer(pattern, text):
        _add_domain(result, match.group(0), base_domain)


# ── Hidden Endpoint Discovery ─────────────────────────────

COMMON_PATHS = [
    "admin", "api", "config", "dashboard", "debug", "docs", "graphql",
    "health", "info", "internal", "login", "logout", "metrics", "monitor",
    "panel", "private", "profile", "register", "reset", "settings", "setup",
    "status", "swagger", "test", "upload", "users", "v1", "v2", "v3",
    "webhooks", "ws", "actuator", "env", "backup", "console", "db",
    "dump", "export", "import", "logs", "management", "proxy", "secret",
    "shell", "trace", "version", ".env", ".git", "robots.txt", "sitemap.xml",
    "wp-admin", "wp-login.php", "phpmyadmin", "adminer", "server-status",
    "server-info", ".well-known/security.txt", "api-docs", "openapi.json",
    "swagger.json", "graphiql",
]


@router.post("/discover")
async def discover_endpoints(data: dict):
    """Probe for hidden/sibling endpoints based on observed traffic patterns."""
    base_url = data.get("base_url", "")
    wordlist = data.get("wordlist", COMMON_PATHS)
    timeout = min(data.get("timeout", 5), 15)
    max_probes = min(data.get("max_probes", 50), 200)
    headers = data.get("headers", {})

    if not base_url:
        raise HTTPException(400, "base_url is required")

    # Normalize base URL
    if not base_url.endswith("/"):
        base_url = base_url.rsplit("/", 1)[0] + "/"

    results = []
    send_headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}

    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
        for path in wordlist[:max_probes]:
            url = base_url + path.lstrip("/")
            try:
                resp = await client.get(url, headers=send_headers or None)
                results.append({
                    "path": path,
                    "url": url,
                    "status_code": resp.status_code,
                    "size": len(resp.content),
                    "content_type": resp.headers.get("content-type", ""),
                    "redirect": resp.headers.get("location", ""),
                    "interesting": resp.status_code not in (404, 403, 401, 400),
                })
            except Exception as e:
                results.append({
                    "path": path,
                    "url": url,
                    "status_code": 0,
                    "size": 0,
                    "error": str(e),
                    "interesting": False,
                })

    interesting = [r for r in results if r.get("interesting")]
    return {
        "results": results,
        "interesting": interesting,
        "total": len(results),
        "found": len(interesting),
    }


# ── API Schema Reconstructor ──────────────────────────────

@router.get("/schema")
def build_schema(domain: str = ""):
    """Auto-build API schema from captured traffic."""
    flows = state.get_flows(limit=5000)

    endpoints: dict[str, dict] = {}

    for flow in flows:
        if domain and domain not in flow.host:
            continue
        if flow.flow_type == "websocket":
            continue

        # Normalize path (strip query)
        path = flow.path.split("?")[0] if flow.path else "/"

        # Generalize path (replace IDs with {id})
        generalized = _generalize_path(path)
        key = f"{flow.host}|{generalized}"

        if key not in endpoints:
            endpoints[key] = {
                "host": flow.host,
                "path": generalized,
                "original_paths": [],
                "methods": {},
            }

        ep = endpoints[key]
        if path not in ep["original_paths"]:
            ep["original_paths"].append(path)
            if len(ep["original_paths"]) > 10:
                ep["original_paths"] = ep["original_paths"][:10]

        method = flow.method
        if method not in ep["methods"]:
            ep["methods"][method] = {
                "count": 0,
                "status_codes": {},
                "request_content_types": set(),
                "response_content_types": set(),
                "query_params": set(),
                "sample_request_body": "",
                "sample_response_body": "",
            }

        m = ep["methods"][method]
        m["count"] += 1
        sc = str(flow.status_code)
        m["status_codes"][sc] = m["status_codes"].get(sc, 0) + 1

        if flow.request_content_type:
            m["request_content_types"].add(flow.request_content_type)
        if flow.response_content_type:
            m["response_content_types"].add(flow.response_content_type)

        # Extract query params
        if "?" in flow.path:
            qs = flow.path.split("?", 1)[1]
            for param in urllib.parse.parse_qs(qs):
                m["query_params"].add(param)

        # Store sample bodies
        if not m["sample_request_body"] and flow.request_body:
            m["sample_request_body"] = flow.request_body[:2000]
        if not m["sample_response_body"] and flow.response_body:
            m["sample_response_body"] = flow.response_body[:2000]

    # Convert sets to lists for JSON serialization
    result = []
    for ep in endpoints.values():
        methods = {}
        for method, data in ep["methods"].items():
            methods[method] = {
                "count": data["count"],
                "status_codes": data["status_codes"],
                "request_content_types": sorted(data["request_content_types"]),
                "response_content_types": sorted(data["response_content_types"]),
                "query_params": sorted(data["query_params"]),
                "sample_request_body": data["sample_request_body"],
                "sample_response_body": data["sample_response_body"],
            }
        result.append({
            "host": ep["host"],
            "path": ep["path"],
            "original_paths": ep["original_paths"],
            "methods": methods,
        })

    result.sort(key=lambda x: (x["host"], x["path"]))
    return {"endpoints": result, "count": len(result)}


def _generalize_path(path: str) -> str:
    """Replace numeric/UUID path segments with placeholders."""
    parts = path.strip("/").split("/")
    result = []
    for part in parts:
        if re.match(r'^\d+$', part):
            result.append("{id}")
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
            result.append("{uuid}")
        elif re.match(r'^[0-9a-f]{24}$', part, re.I):
            result.append("{objectId}")
        else:
            result.append(part)
    return "/" + "/".join(result) if result else "/"
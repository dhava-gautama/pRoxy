"""Generate an OpenAPI 3.0 spec from captured traffic.

Inspired by alufers/mitmproxy2swagger (MIT). pRoxy captures flows live in
ProxyState, so there's no flow-file/ignore-list dance — we build the spec
straight from captured FlowRecords, reusing recon's path templating.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from api.routes.recon import _generalize_path
from state.shared import ProxyState

router = APIRouter(prefix="/api/openapi", tags=["openapi"])
state = ProxyState()

_PLACEHOLDERS = {"{id}": ("integer", None), "{uuid}": ("string", "uuid"), "{objectId}": ("string", None)}
_MAX_SAMPLES = 50          # bodies inspected per (path, method, status)
_MAX_BODY = 200_000        # skip inferring from bodies larger than this


# ── JSON schema inference ──────────────────────────────────────────────

def _infer_schema(value: Any) -> dict:
    """Infer an OpenAPI schema object from a parsed JSON value."""
    if value is None:
        return {"nullable": True}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        items: dict = {}
        for el in value:
            items = _merge_schemas(items, _infer_schema(el))
        return {"type": "array", "items": items or {}}
    if isinstance(value, dict):
        props = {k: _infer_schema(v) for k, v in value.items()}
        schema: dict = {"type": "object"}
        if props:
            schema["properties"] = props
            schema["required"] = sorted(value.keys())
        return schema
    return {}


def _merge_schemas(a: dict, b: dict) -> dict:
    """Merge two inferred schemas (across multiple samples / array items)."""
    if not a:
        return dict(b)
    if not b:
        return dict(a)

    ta, tb = a.get("type"), b.get("type")
    # widen integer + number -> number
    if {ta, tb} == {"integer", "number"}:
        ta = tb = "number"
    if ta != tb:
        # conflicting types -> leave unconstrained, but preserve nullability
        merged: dict = {}
        if a.get("nullable") or b.get("nullable"):
            merged["nullable"] = True
        return merged

    merged = {"type": ta} if ta else {}
    if a.get("nullable") or b.get("nullable"):
        merged["nullable"] = True
    if a.get("format") and a.get("format") == b.get("format"):
        merged["format"] = a["format"]

    if ta == "object":
        props_a, props_b = a.get("properties", {}), b.get("properties", {})
        keys = set(props_a) | set(props_b)
        if keys:
            merged["properties"] = {}
            for k in sorted(keys):
                if k in props_a and k in props_b:
                    merged["properties"][k] = _merge_schemas(props_a[k], props_b[k])
                else:
                    merged["properties"][k] = props_a.get(k) or props_b.get(k)
            # required only if present in BOTH samples
            req_a, req_b = set(a.get("required", [])), set(b.get("required", []))
            req = sorted(req_a & req_b)
            if req:
                merged["required"] = req
    elif ta == "array":
        merged["items"] = _merge_schemas(a.get("items", {}), b.get("items", {})) or {}
    return merged


def _parse_body(body: str, content_type: str) -> tuple[Optional[Any], Optional[str]]:
    """Return (parsed_value, media_type) for a body we can model, else (None, None)."""
    if not body or len(body) > _MAX_BODY:
        return None, None
    ct = (content_type or "").lower()
    if "json" in ct or (not ct and body.lstrip()[:1] in "{["):
        try:
            return json.loads(body), "application/json"
        except (ValueError, TypeError):
            return None, None
    if "x-www-form-urlencoded" in ct:
        parsed = {k: (v[0] if len(v) == 1 else v) for k, v in urllib.parse.parse_qs(body).items()}
        return parsed, "application/x-www-form-urlencoded"
    return None, None


# ── Path templating (OpenAPI needs unique param names) ─────────────────

def _sanitize(seg: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]", "", seg) or "param"


def _openapi_path(generalized: str) -> tuple[str, list[dict]]:
    """Turn a recon-generalized path into an OpenAPI path + unique path params."""
    segs = [s for s in generalized.strip("/").split("/") if s != ""]
    out: list[str] = []
    params: list[dict] = []
    used: set[str] = set()
    for i, seg in enumerate(segs):
        if seg in _PLACEHOLDERS:
            ptype, pfmt = _PLACEHOLDERS[seg]
            prev = segs[i - 1] if i > 0 and segs[i - 1] not in _PLACEHOLDERS else ""
            if prev:
                base = _sanitize(prev)
                base = base[:-1] if base.endswith("s") and len(base) > 1 else base
                name = base + "Id"
            else:
                name = seg.strip("{}")
            uniq, n = name, 2
            while uniq in used:
                uniq, n = f"{name}{n}", n + 1
            used.add(uniq)
            schema = {"type": ptype}
            if pfmt:
                schema["format"] = pfmt
            params.append({"name": uniq, "in": "path", "required": True, "schema": schema})
            out.append("{" + uniq + "}")
        else:
            out.append(seg)
    return ("/" + "/".join(out)) if out else "/", params


# ── Spec assembly ──────────────────────────────────────────────────────

def _collect(domain: str) -> tuple[dict, set[str]]:
    """Group in-scope flows into endpoints[(oapi_path, method)] -> aggregation."""
    endpoints: dict[tuple[str, str], dict] = {}
    servers: set[str] = set()

    for flow in state.get_flows(limit=5000):
        if flow.flow_type == "websocket":
            continue
        if domain and domain not in flow.host:
            continue
        if not flow.host or not flow.method:
            continue

        raw_path = (flow.path or "/").split("?", 1)[0]
        oapi_path, path_params = _openapi_path(_generalize_path(raw_path))
        method = flow.method.lower()
        key = (oapi_path, method)

        if flow.scheme and flow.host:
            base = f"{flow.scheme}://{flow.host}"
            if flow.port and flow.port not in (80, 443):
                base += f":{flow.port}"
            servers.add(base)

        ep = endpoints.setdefault(key, {
            "path": oapi_path, "method": method, "path_params": path_params,
            "query_params": set(), "req_schema": {}, "req_media": None,
            "req_example": None, "responses": {}, "count": 0,
        })
        ep["count"] += 1

        # query params
        if "?" in (flow.path or ""):
            for p in urllib.parse.parse_qs(flow.path.split("?", 1)[1]):
                ep["query_params"].add(p)

        # request body
        if ep["count"] <= _MAX_SAMPLES:
            val, media = _parse_body(flow.request_body, flow.request_content_type)
            if media:
                ep["req_media"] = media
                ep["req_schema"] = _merge_schemas(ep["req_schema"], _infer_schema(val))
                if ep["req_example"] is None:
                    ep["req_example"] = val

        # response by status code
        sc = str(flow.status_code or "default")
        resp = ep["responses"].setdefault(sc, {"schema": {}, "media": None, "example": None, "reason": flow.reason, "n": 0})
        resp["n"] += 1
        if resp["n"] <= _MAX_SAMPLES:
            val, media = _parse_body(flow.response_body, flow.response_content_type)
            if media:
                resp["media"] = media
                resp["schema"] = _merge_schemas(resp["schema"], _infer_schema(val))
                if resp["example"] is None:
                    resp["example"] = val

    return endpoints, servers


def _build_spec(domain: str, include_examples: bool) -> dict:
    endpoints, servers = _collect(domain)

    paths: dict[str, dict] = {}
    for (oapi_path, method), ep in sorted(endpoints.items()):
        operation: dict = {
            "summary": f"{method.upper()} {oapi_path}",
            "parameters": list(ep["path_params"]) + [
                {"name": q, "in": "query", "required": False, "schema": {"type": "string"}}
                for q in sorted(ep["query_params"])
            ],
            "responses": {},
        }

        if ep["req_media"]:
            media_obj: dict = {"schema": ep["req_schema"] or {}}
            if include_examples and ep["req_example"] is not None:
                media_obj["example"] = ep["req_example"]
            operation["requestBody"] = {"content": {ep["req_media"]: media_obj}}

        for sc, resp in sorted(ep["responses"].items()):
            entry: dict = {"description": resp.get("reason") or f"Response {sc}"}
            if resp["media"]:
                media_obj = {"schema": resp["schema"] or {}}
                if include_examples and resp["example"] is not None:
                    media_obj["example"] = resp["example"]
                entry["content"] = {resp["media"]: media_obj}
            operation["responses"][sc] = entry
        if not operation["responses"]:
            operation["responses"]["default"] = {"description": "No response captured"}

        paths.setdefault(oapi_path, {})[method] = operation

    spec: dict = {
        "openapi": "3.0.3",
        "info": {
            "title": f"pRoxy Captured API{' — ' + domain if domain else ''}",
            "version": "1.0.0",
            "description": "Auto-generated from traffic captured by pRoxy.",
        },
        "paths": paths,
    }
    if servers:
        spec["servers"] = [{"url": u} for u in sorted(servers)]
    return spec


# ── Routes ─────────────────────────────────────────────────────────────

@router.get("/endpoints")
def list_endpoints(domain: str = ""):
    """Lightweight preview of discovered endpoints (for the UI)."""
    endpoints, _ = _collect(domain)
    items = [
        {"method": m.upper(), "path": p, "count": ep["count"],
         "statuses": sorted(ep["responses"].keys())}
        for (p, m), ep in sorted(endpoints.items())
    ]
    return {"endpoints": items, "count": len(items)}


@router.get("/spec")
def get_spec(domain: str = "", include_examples: bool = False, format: str = "json"):
    """Generate an OpenAPI 3.0 spec from captured traffic.

    include_examples=true embeds real captured request/response bodies VERBATIM,
    which may contain tokens/credentials/PII — intended for local use only.
    format=yaml returns the spec as YAML instead of JSON.
    """
    spec = _build_spec(domain, include_examples)
    if format == "yaml":
        try:
            import yaml
        except ImportError:
            raise HTTPException(400, "YAML output requires PyYAML (pip install pyyaml)")
        text = yaml.safe_dump(spec, sort_keys=False, default_flow_style=False, allow_unicode=True)
        return Response(content=text, media_type="application/yaml")
    return spec

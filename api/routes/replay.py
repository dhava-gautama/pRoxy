from __future__ import annotations

import asyncio
import json
import random
import re
import string
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends,  APIRouter, HTTPException, Query
from pydantic import BaseModel, model_validator

from api.auth import create_auth_dependencies
from api.constants import SessionStatus, FallbackAction
from api.utils import generate_timestamp_id
from state.models import ReplayRequest, FlowRecord, FuzzConfig, SavedSequence, SequenceStep
from state.shared import ProxyState

router = APIRouter(prefix="/api/replay", tags=["replay"], dependencies=create_auth_dependencies())
state = ProxyState()


# ── Traffic Replay Models ──────────────────────────────────────

class ReplaySession(BaseModel):
    """Represents a traffic replay session."""
    id: str
    name: str
    description: str = ""
    flows: List[str] = []  # Flow IDs
    created_at: float
    status: SessionStatus = SessionStatus.CREATED
    config: Dict[str, Any] = {}

    @model_validator(mode='after')
    def validate_session(self) -> 'ReplaySession':
        if not self.name.strip():
            raise ValueError("Session name cannot be empty")
        # Status validation is handled by SessionStatus enum
        return self


class ReplayConfig(BaseModel):
    """Configuration for replay operations."""
    concurrent_requests: int = 1
    delay_between_requests: float = 0.0
    follow_redirects: bool = True
    preserve_timing: bool = False
    replace_host: Optional[str] = None
    replace_headers: Dict[str, str] = {}
    filter_domains: List[str] = []
    max_duration: int = 300  # seconds

    @model_validator(mode='after')
    def validate_config(self) -> 'ReplayConfig':
        if self.concurrent_requests < 1 or self.concurrent_requests > 50:
            raise ValueError("Concurrent requests must be between 1 and 50")
        if self.delay_between_requests < 0:
            raise ValueError("Delay cannot be negative")
        if self.max_duration < 1 or self.max_duration > 3600:
            raise ValueError("Max duration must be between 1 and 3600 seconds")
        return self


class ServerReplayRule(BaseModel):
    """Rule for server replay - return recorded responses."""
    id: str
    name: str
    enabled: bool = True
    match_method: bool = True
    match_host: bool = True
    match_path: bool = True
    match_query: bool = False
    match_headers: List[str] = []  # Header names to match
    flows: List[str] = []  # Recorded flow IDs to replay
    fallback_action: FallbackAction = FallbackAction.PASSTHROUGH

    @model_validator(mode='after')
    def validate_rule(self) -> 'ServerReplayRule':
        if not self.name.strip():
            raise ValueError("Rule name cannot be empty")
        # Fallback action validation is handled by FallbackAction enum
        return self


class ContentInjectionRule(BaseModel):
    """Rule for content injection - fetch content from another URL."""
    id: str
    name: str
    enabled: bool = True
    match_pattern: str  # Pattern to match original URL
    source_url: str     # URL to fetch content from
    is_regex: bool = False
    preserve_headers: bool = True
    custom_headers: Dict[str, str] = {}
    timeout: int = 30

    @model_validator(mode='after')
    def validate_rule(self) -> 'ContentInjectionRule':
        if not self.name.strip():
            raise ValueError("Rule name cannot be empty")
        if not self.match_pattern.strip():
            raise ValueError("Match pattern cannot be empty")
        if not self.source_url.strip():
            raise ValueError("Source URL cannot be empty")
        return self


# Global storage
_replay_sessions: Dict[str, ReplaySession] = {}
_server_replay_rules: Dict[str, ServerReplayRule] = {}
_content_injection_rules: Dict[str, ContentInjectionRule] = {}
_active_replays: Dict[str, asyncio.Task] = {}


async def _do_request(method: str, url: str, headers: dict, body: str) -> dict:
    """Execute a single HTTP request and return result + store as flow."""
    send_headers = {k: v for k, v in (headers or {}).items() if k.lower() != "content-length"}
    start = time.time()
    async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
        response = await client.request(
            method=method,
            url=url,
            headers=send_headers or None,
            content=body.encode("utf-8") if body else None,
        )
    duration = round((time.time() - start) * 1000, 1)

    resp_headers = dict(response.headers)
    ct = resp_headers.get("content-type", "")
    try:
        resp_body = response.text if response.text else ""
    except Exception:
        resp_body = f"<binary {len(response.content)} bytes>"

    parsed = urllib.parse.urlparse(url)
    flow = FlowRecord(
        id=f"replay-{int(time.time()*1000)}",
        timestamp=time.time(),
        method=method,
        scheme=parsed.scheme,
        host=parsed.hostname or "",
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        path=parsed.path + ("?" + parsed.query if parsed.query else ""),
        url=url,
        request_headers=headers,
        request_body=body,
        request_content_type=headers.get("content-type", ""),
        status_code=response.status_code,
        reason=response.reason_phrase or "",
        response_headers=resp_headers,
        response_body=resp_body[:512_000],
        response_content_type=ct,
        response_size=len(response.content),
        completed=True,
        duration_ms=duration,
    )
    state.store_flow(flow)
    state.traffic_queue.put(flow)

    return {
        "id": flow.id,
        "status_code": response.status_code,
        "reason": response.reason_phrase,
        "headers": resp_headers,
        "body": resp_body[:512_000],
        "duration_ms": duration,
    }


@router.post("")
async def replay_request(req: ReplayRequest):
    """Send an HTTP request and return the response."""
    try:
        return await _do_request(req.method, req.url, req.headers, req.body)
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, f"Replay error: {e}")


# ── Fuzzer ────────────────────────────────────────────────────

def _generate_fuzz_value(var_type: str, iteration: int) -> str:
    """Generate a fuzz value based on type specification."""
    parts = var_type.split(":", 1)
    kind = parts[0]
    args = parts[1] if len(parts) > 1 else ""

    if kind == "range":
        try:
            start, end = args.split(",", 1)
            return str(int(start) + iteration)
        except Exception:
            return str(iteration)
    elif kind == "wordlist":
        words = [w.strip() for w in args.split(",")]
        return words[iteration % len(words)] if words else str(iteration)
    elif kind == "random":
        length = int(args) if args.isdigit() else 8
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))
    elif kind == "uuid":
        import uuid
        return str(uuid.uuid4())
    else:
        return str(iteration)


def _substitute_fuzz(text: str, variables: dict[str, str], iteration: int) -> str:
    """Replace {{fuzz.varname}} with generated values."""
    if not text or "{{fuzz." not in text:
        return text
    result = text.replace("{{fuzz.i}}", str(iteration))
    for name, var_type in variables.items():
        placeholder = "{{fuzz." + name + "}}"
        if placeholder in result:
            result = result.replace(placeholder, _generate_fuzz_value(var_type, iteration))
    return result


@router.post("/fuzz")
async def fuzz_request(data: dict):
    """Run a request multiple times with variable substitution."""
    try:
        method = data.get("method", "GET")
        url_template = data.get("url", "")
        headers_template = data.get("headers", {})
        body_template = data.get("body", "")
        iterations = min(data.get("iterations", 10), 1000)
        variables = data.get("variables", {})
        delay_ms = min(max(data.get("delay_ms", 0), 0), 10_000)  # cap per-iteration delay

        results = []
        for i in range(iterations):
            url = _substitute_fuzz(url_template, variables, i)
            body = _substitute_fuzz(body_template, variables, i)
            headers = {}
            for k, v in headers_template.items():
                headers[k] = _substitute_fuzz(v, variables, i)

            try:
                result = await _do_request(method, url, headers, body)
                results.append({
                    "iteration": i,
                    "status_code": result["status_code"],
                    "duration_ms": result["duration_ms"],
                    "size": len(result.get("body", "")),
                    "id": result["id"],
                })
            except Exception as e:
                results.append({
                    "iteration": i,
                    "status_code": 0,
                    "duration_ms": 0,
                    "size": 0,
                    "error": str(e),
                })

            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000)

        return {"results": results}
    except Exception as e:
        raise HTTPException(500, f"Fuzz error: {e}")


# ── Sequences ─────────────────────────────────────────────────

def _extract_value(body: str, headers: dict, spec: str) -> str:
    """Extract a value from response using spec like 'json:path.to.field'."""
    parts = spec.split(":", 1)
    kind = parts[0]
    path = parts[1] if len(parts) > 1 else ""

    if kind == "json" and path:
        try:
            import json
            obj = json.loads(body)
            for key in path.split("."):
                if isinstance(obj, dict):
                    obj = obj.get(key, "")
                elif isinstance(obj, list) and key.isdigit():
                    obj = obj[int(key)]
                else:
                    return ""
            return str(obj) if obj is not None else ""
        except Exception:
            return ""
    elif kind == "header" and path:
        for k, v in headers.items():
            if k.lower() == path.lower():
                return v
        return ""
    elif kind == "regex" and path:
        try:
            m = re.search(path, body)
            return m.group(1) if m and m.groups() else (m.group(0) if m else "")
        except Exception:
            return ""
    return ""


def _apply_variables(text: str, variables: dict[str, str]) -> str:
    """Replace {{var.name}} in text with extracted values."""
    if not text or "{{var." not in text:
        return text
    for name, value in variables.items():
        text = text.replace("{{var." + name + "}}", value)
    return text


@router.post("/sequence")
async def run_sequence(data: dict):
    """Run a sequence of requests with variable extraction and chaining."""
    try:
        steps = data.get("steps", [])
        results = []
        extracted_vars: dict[str, str] = {}

        for i, step_data in enumerate(steps):
            step = SequenceStep(**step_data)

            # Substitute variables
            url = _apply_variables(step.url, extracted_vars)
            body = _apply_variables(step.body, extracted_vars)
            headers = {}
            for k, v in step.headers.items():
                headers[k] = _apply_variables(v, extracted_vars)

            try:
                result = await _do_request(step.method, url, headers, body)

                # Extract variables for chaining
                for var_name, extract_spec in step.extract.items():
                    extracted_vars[var_name] = _extract_value(
                        result.get("body", ""),
                        result.get("headers", {}),
                        extract_spec,
                    )

                results.append({
                    "step": i,
                    "name": step.name,
                    "status_code": result["status_code"],
                    "duration_ms": result["duration_ms"],
                    "id": result["id"],
                    "extracted": {k: extracted_vars[k] for k in step.extract if k in extracted_vars},
                })
            except Exception as e:
                results.append({
                    "step": i,
                    "name": step.name,
                    "status_code": 0,
                    "duration_ms": 0,
                    "error": str(e),
                })

        return {"results": results, "variables": extracted_vars}
    except Exception as e:
        raise HTTPException(500, f"Sequence error: {e}")


# ── Sequence CRUD ─────────────────────────────────────────────

@router.get("/sequences")
def list_sequences():
    return [s.model_dump() for s in state.get_sequences()]


@router.post("/sequences")
async def create_sequence(data: dict):
    seq = SavedSequence(
        id=data.get("id") or f"seq-{int(time.time()*1000)}",
        name=data.get("name", "Untitled"),
        steps=data.get("steps", []),
    )
    return state.save_sequence(seq).model_dump()


@router.delete("/sequences/{seq_id}")
def delete_sequence(seq_id: str):
    if not state.delete_sequence(seq_id):
        raise HTTPException(404, "Sequence not found")
    return {"ok": True}


# ── Traffic Replay System ─────────────────────────────────────

@router.get("/sessions")
def list_replay_sessions() -> List[ReplaySession]:
    """List all replay sessions."""
    return list(_replay_sessions.values())


@router.post("/sessions")
def create_replay_session(name: str, description: str = "") -> ReplaySession:
    """Create a new replay session."""
    session_id = f"session_{int(time.time() * 1000)}"
    session = ReplaySession(
        id=session_id,
        name=name,
        description=description,
        created_at=time.time()
    )
    _replay_sessions[session_id] = session
    return session


@router.get("/sessions/{session_id}")
def get_replay_session(session_id: str) -> ReplaySession:
    """Get replay session details."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")
    return _replay_sessions[session_id]


@router.delete("/sessions/{session_id}")
def delete_replay_session(session_id: str) -> dict:
    """Delete replay session."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    # Stop active replay if running
    if session_id in _active_replays:
        _active_replays[session_id].cancel()
        del _active_replays[session_id]

    del _replay_sessions[session_id]
    return {"message": "Session deleted"}


@router.post("/sessions/{session_id}/record")
def start_recording(session_id: str, filter_domains: List[str] = Query(default=[])) -> dict:
    """Start recording traffic to session."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    session = _replay_sessions[session_id]
    if session.status != "created":
        raise HTTPException(400, "Session must be in 'created' status to start recording")

    session.status = "recording"
    session.config["filter_domains"] = filter_domains
    session.config["recording_start"] = time.time()

    # Register recording with proxy state
    state.set_recording_session(session_id, filter_domains)

    return {"message": "Recording started"}


@router.post("/sessions/{session_id}/stop-record")
def stop_recording(session_id: str) -> dict:
    """Stop recording traffic."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    session = _replay_sessions[session_id]
    if session.status != "recording":
        raise HTTPException(400, "Session is not recording")

    # Get recorded flows from proxy state
    recorded_flows = state.stop_recording_session(session_id)

    session.flows = recorded_flows
    session.status = "completed"
    session.config["recording_end"] = time.time()

    return {"message": f"Recording stopped, {len(recorded_flows)} flows recorded"}


@router.post("/sessions/{session_id}/replay")
async def start_replay(session_id: str, config: ReplayConfig) -> dict:
    """Start replaying recorded traffic."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    session = _replay_sessions[session_id]
    if not session.flows:
        raise HTTPException(400, "No flows recorded in session")

    if session_id in _active_replays:
        raise HTTPException(400, "Replay already running for this session")

    session.status = "replaying"
    session.config["replay_config"] = config.model_dump()

    # Start replay task
    task = asyncio.create_task(_execute_replay(session, config))
    _active_replays[session_id] = task

    return {"message": "Replay started"}


@router.post("/sessions/{session_id}/stop")
def stop_replay(session_id: str) -> dict:
    """Stop active replay."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    if session_id not in _active_replays:
        raise HTTPException(400, "No active replay for this session")

    _active_replays[session_id].cancel()
    del _active_replays[session_id]

    _replay_sessions[session_id].status = "completed"

    return {"message": "Replay stopped"}


# ── Server Replay Rules ───────────────────────────────────────

@router.get("/server-rules")
def list_server_replay_rules() -> List[ServerReplayRule]:
    """List server replay rules."""
    return list(_server_replay_rules.values())


@router.post("/server-rules")
def create_server_replay_rule(rule: ServerReplayRule) -> ServerReplayRule:
    """Create server replay rule."""
    rule_id = f"rule_{int(time.time() * 1000)}"
    rule.id = rule_id
    _server_replay_rules[rule_id] = rule

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_server_replay_rules(_server_replay_rules)

    return rule


@router.put("/server-rules/{rule_id}")
def update_server_replay_rule(rule_id: str, rule: ServerReplayRule) -> ServerReplayRule:
    """Update server replay rule."""
    if rule_id not in _server_replay_rules:
        raise HTTPException(404, "Rule not found")

    rule.id = rule_id
    _server_replay_rules[rule_id] = rule

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_server_replay_rules(_server_replay_rules)

    return rule


@router.delete("/server-rules/{rule_id}")
def delete_server_replay_rule(rule_id: str) -> dict:
    """Delete server replay rule."""
    if rule_id not in _server_replay_rules:
        raise HTTPException(404, "Rule not found")

    del _server_replay_rules[rule_id]

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_server_replay_rules(_server_replay_rules)

    return {"message": "Rule deleted"}


@router.post("/server-rules/{rule_id}/toggle")
def toggle_server_replay_rule(rule_id: str) -> ServerReplayRule:
    """Toggle server replay rule enabled state."""
    if rule_id not in _server_replay_rules:
        raise HTTPException(404, "Rule not found")

    rule = _server_replay_rules[rule_id]
    rule.enabled = not rule.enabled

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_server_replay_rules(_server_replay_rules)

    return rule


# ── Content Injection Rules ───────────────────────────────────

@router.get("/content-injection")
def list_content_injection_rules() -> List[ContentInjectionRule]:
    """List content injection rules."""
    return list(_content_injection_rules.values())


@router.post("/content-injection")
def create_content_injection_rule(rule: ContentInjectionRule) -> ContentInjectionRule:
    """Create content injection rule."""
    rule_id = f"inject_{int(time.time() * 1000)}"
    rule.id = rule_id
    _content_injection_rules[rule_id] = rule

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_content_injection_rules(_content_injection_rules)

    return rule


@router.put("/content-injection/{rule_id}")
def update_content_injection_rule(rule_id: str, rule: ContentInjectionRule) -> ContentInjectionRule:
    """Update content injection rule."""
    if rule_id not in _content_injection_rules:
        raise HTTPException(404, "Rule not found")

    rule.id = rule_id
    _content_injection_rules[rule_id] = rule

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_content_injection_rules(_content_injection_rules)

    return rule


@router.delete("/content-injection/{rule_id}")
def delete_content_injection_rule(rule_id: str) -> dict:
    """Delete content injection rule."""
    if rule_id not in _content_injection_rules:
        raise HTTPException(404, "Rule not found")

    del _content_injection_rules[rule_id]

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_content_injection_rules(_content_injection_rules)

    return {"message": "Rule deleted"}


@router.post("/content-injection/{rule_id}/toggle")
def toggle_content_injection_rule(rule_id: str) -> ContentInjectionRule:
    """Toggle content injection rule enabled state."""
    if rule_id not in _content_injection_rules:
        raise HTTPException(404, "Rule not found")

    rule = _content_injection_rules[rule_id]
    rule.enabled = not rule.enabled

    # Update proxy addon
    if hasattr(state, 'proxy_addon'):
        state.proxy_addon.update_content_injection_rules(_content_injection_rules)

    return rule


# ── HAR Export ────────────────────────────────────────────────

@router.get("/flows/{flow_id}/curl")
def export_flow_curl(flow_id: str) -> dict:
    """Export flow as curl command."""
    flow = state.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, "Flow not found")

    curl_cmd = _generate_curl_command(flow)
    return {"curl_command": curl_cmd}


@router.post("/sessions/{session_id}/export-curl")
def export_session_curl(session_id: str) -> dict:
    """Export all session flows as curl commands."""
    if session_id not in _replay_sessions:
        raise HTTPException(404, "Session not found")

    session = _replay_sessions[session_id]
    curl_commands = []

    for flow_id in session.flows:
        flow = state.get_flow(flow_id)
        if flow:
            curl_commands.append(_generate_curl_command(flow))

    return {"curl_commands": curl_commands}


@router.get("/flows/{flow_id}/har")
def export_flow_har(flow_id: str) -> dict:
    """Export flow as HAR (HTTP Archive) format."""
    flow = state.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, "Flow not found")

    har_entry = _generate_har_entry(flow)
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "pRoxy", "version": "1.0"},
            "entries": [har_entry]
        }
    }


@router.post("/export-har")
def export_all_har(filter_domains: List[str] = Query(default=[]), limit: int = 1000) -> dict:
    """Export flows as HAR format."""
    flows = state.get_flows(limit=limit)

    if filter_domains:
        flows = [f for f in flows if f.host in filter_domains]

    entries = []
    for flow in flows:
        if flow.completed:  # Only include completed flows in HAR
            entries.append(_generate_har_entry(flow))

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "pRoxy", "version": "1.0"},
            "entries": entries
        }
    }


# ── Helper Functions ───────────────────────────────────────────

async def _execute_replay(session: ReplaySession, config: ReplayConfig) -> None:
    """Execute traffic replay asynchronously."""
    client = httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=config.follow_redirects,
        verify=False
    )

    try:
        start_time = time.time()

        for i, flow_id in enumerate(session.flows):
            # Check for cancellation and timeout
            if time.time() - start_time > config.max_duration:
                break

            flow = state.get_flow(flow_id)
            if not flow:
                continue

            # Apply domain filter
            if config.filter_domains and flow.host not in config.filter_domains:
                continue

            # Build request
            url = f"{flow.scheme}://{flow.host}:{flow.port}{flow.path}"
            if config.replace_host:
                url = url.replace(f"//{flow.host}", f"//{config.replace_host}")

            headers = flow.request_headers.copy()
            headers.update(config.replace_headers)

            # Execute request
            try:
                response = await client.request(
                    method=flow.method,
                    url=url,
                    headers=headers,
                    content=flow.request_body.encode() if flow.request_body else None
                )

                print(f"Replayed: {flow.method} {url} -> {response.status_code}")

            except Exception as e:
                print(f"Replay failed: {flow.method} {url} -> {e}")

            # Delay between requests
            if i < len(session.flows) - 1:
                await asyncio.sleep(config.delay_between_requests)

        session.status = "completed"

    except asyncio.CancelledError:
        session.status = "completed"
        raise
    except Exception as e:
        session.status = "error"
        session.config["error"] = str(e)
    finally:
        await client.aclose()
        if session.id in _active_replays:
            del _active_replays[session.id]


def _generate_curl_command(flow: FlowRecord) -> str:
    """Generate curl command for a flow."""
    parts = [
        "curl",
        f"'{flow.scheme}://{flow.host}:{flow.port}{flow.path}'",
        f"-X {flow.method}"
    ]

    # Add headers
    for name, value in flow.request_headers.items():
        if name.lower() not in ('host', 'content-length'):
            parts.append(f"-H '{name}: {value}'")

    # Add body
    if flow.request_body:
        if len(flow.request_body) < 1000:
            parts.append(f"-d '{flow.request_body}'")
        else:
            parts.append(f"-d '@-'  # Body too large, pipe from stdin")

    return " \\\n  ".join(parts)


def _generate_har_entry(flow: FlowRecord) -> dict:
    """Generate HAR entry for a flow."""
    entry = {
        "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime(flow.timestamp)),
        "time": flow.duration_ms or 0,
        "request": {
            "method": flow.method,
            "url": flow.url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in flow.request_headers.items()],
            "queryString": [],
            "headersSize": -1,
            "bodySize": len(flow.request_body) if flow.request_body else 0,
        },
        "response": {
            "status": flow.status_code or 0,
            "statusText": flow.reason or "",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in (flow.response_headers or {}).items()],
            "content": {
                "size": flow.response_size or 0,
                "mimeType": flow.response_content_type or "application/octet-stream",
                "text": flow.response_body or ""
            },
            "headersSize": -1,
            "bodySize": flow.response_size or 0,
        },
        "cache": {},
        "timings": {
            "send": 0,
            "wait": flow.duration_ms or 0,
            "receive": 0
        }
    }

    # Add request body if present
    if flow.request_body:
        entry["request"]["postData"] = {
            "mimeType": flow.request_content_type or "text/plain",
            "text": flow.request_body
        }

    return entry


def get_replay_sessions() -> Dict[str, ReplaySession]:
    """Get all replay sessions for addon access."""
    return _replay_sessions


def get_server_replay_rules() -> Dict[str, ServerReplayRule]:
    """Get all server replay rules for addon access."""
    return _server_replay_rules


def get_content_injection_rules() -> Dict[str, ContentInjectionRule]:
    """Get all content injection rules for addon access."""
    return _content_injection_rules
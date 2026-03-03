from __future__ import annotations

import fnmatch
import json
import logging
import queue
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from state.models import (
    DNSSettings,
    FlowRecord,
    InterceptedFlow,
    ProxySettings,
)

MAX_FLOWS = 10_000
_logger = logging.getLogger("pRoxy.state")


class ProxyState:
    """Thread-safe singleton holding all shared proxy state."""

    _instance: Optional[ProxyState] = None
    _lock = threading.Lock()

    def __new__(cls) -> ProxyState:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self) -> None:
        self._flows_lock = threading.Lock()
        self._flows: OrderedDict[str, FlowRecord] = OrderedDict()

        self._settings_lock = threading.Lock()
        self._settings = ProxySettings()

        self._dns_lock = threading.Lock()
        self._dns = DNSSettings()

        # mitmproxy thread → FastAPI drain task
        self.traffic_queue: queue.Queue[FlowRecord] = queue.Queue()

        # Intercept: flow_id → InterceptedFlow + threading.Event
        self._intercept_lock = threading.Lock()
        self._intercept_queue: OrderedDict[str, tuple[InterceptedFlow, threading.Event]] = OrderedDict()

        # Persistence
        self._persistence_dir = Path.home() / ".pRoxy"
        self._load_persisted()

    # ── Persistence ─────────────────────────────────────────

    def _persist_settings(self) -> None:
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "settings.json"
            path.write_text(self._settings.model_dump_json(indent=2))
        except Exception as e:
            _logger.warning("Failed to persist settings: %s", e)

    def _persist_dns(self) -> None:
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "dns.json"
            path.write_text(self._dns.model_dump_json(indent=2))
        except Exception as e:
            _logger.warning("Failed to persist DNS: %s", e)

    def _load_persisted(self) -> None:
        try:
            path = self._persistence_dir / "settings.json"
            if path.exists():
                data = json.loads(path.read_text())
                self._settings = ProxySettings(**data)
                _logger.info("Loaded persisted settings from %s", path)
        except Exception as e:
            _logger.warning("Failed to load persisted settings: %s", e)
        try:
            path = self._persistence_dir / "dns.json"
            if path.exists():
                data = json.loads(path.read_text())
                self._dns = DNSSettings(**data)
                _logger.info("Loaded persisted DNS from %s", path)
        except Exception as e:
            _logger.warning("Failed to load persisted DNS: %s", e)

    # ── Flow storage ──────────────────────────────────────────

    def store_flow(self, flow: FlowRecord) -> None:
        with self._flows_lock:
            self._flows[flow.id] = flow
            while len(self._flows) > MAX_FLOWS:
                self._flows.popitem(last=False)

    def get_flow(self, flow_id: str) -> Optional[FlowRecord]:
        with self._flows_lock:
            return self._flows.get(flow_id)

    def get_flows(self, limit: int = 200, offset: int = 0) -> list[FlowRecord]:
        with self._flows_lock:
            items = list(self._flows.values())
        items.reverse()
        return items[offset : offset + limit]

    def delete_flow(self, flow_id: str) -> bool:
        with self._flows_lock:
            return self._flows.pop(flow_id, None) is not None

    def clear_flows(self) -> int:
        with self._flows_lock:
            n = len(self._flows)
            self._flows.clear()
            return n

    def search_flows(self, query: str, is_regex: bool = False, limit: int = 200) -> list[FlowRecord]:
        with self._flows_lock:
            items = list(self._flows.values())
        items.reverse()
        results = []
        try:
            pattern = re.compile(query, re.IGNORECASE) if is_regex else None
        except re.error:
            return []
        for f in items:
            if len(results) >= limit:
                break
            searchable = f"{f.method} {f.url} {f.host} {f.path} {f.request_body} {f.response_body}"
            for v in f.request_headers.values():
                searchable += f" {v}"
            for v in f.response_headers.values():
                searchable += f" {v}"
            if pattern:
                if pattern.search(searchable):
                    results.append(f)
            else:
                if query.lower() in searchable.lower():
                    results.append(f)
        return results

    # ── Scope check ───────────────────────────────────────────

    def is_in_scope(self, host: str) -> bool:
        with self._settings_lock:
            patterns = self._settings.scope_patterns
        if not patterns:
            return True  # empty scope = capture everything
        return any(fnmatch.fnmatch(host, p) for p in patterns)

    # ── Settings ──────────────────────────────────────────────

    def get_settings(self) -> ProxySettings:
        with self._settings_lock:
            return self._settings.model_copy()

    def update_settings(self, patch: dict) -> ProxySettings:
        with self._settings_lock:
            data = self._settings.model_dump()
            data.update(patch)
            self._settings = ProxySettings(**data)
            self._persist_settings()
            return self._settings.model_copy()

    # ── DNS ───────────────────────────────────────────────────

    def get_dns(self) -> DNSSettings:
        with self._dns_lock:
            return self._dns.model_copy()

    def update_dns(self, patch: dict) -> DNSSettings:
        with self._dns_lock:
            data = self._dns.model_dump()
            data.update(patch)
            self._dns = DNSSettings(**data)
            self._persist_dns()
            return self._dns.model_copy()

    # ── Intercept queue ───────────────────────────────────────

    def enqueue_intercept(self, flow: InterceptedFlow) -> threading.Event:
        event = threading.Event()
        with self._intercept_lock:
            self._intercept_queue[flow.id + ":" + flow.phase] = (flow, event)
        return event

    def get_intercept_queue(self) -> list[InterceptedFlow]:
        with self._intercept_lock:
            return [item[0] for item in self._intercept_queue.values()]

    def resolve_intercept(self, key: str, action: str,
                          modified_body: str | None = None,
                          modified_headers: dict[str, str] | None = None) -> bool:
        with self._intercept_lock:
            entry = self._intercept_queue.get(key)
            if entry is None:
                return False
            intercepted, event = entry
            intercepted.action = action
            intercepted.modified_body = modified_body
            intercepted.modified_headers = modified_headers
            event.set()
            return True

    def pop_resolved(self, key: str) -> Optional[InterceptedFlow]:
        with self._intercept_lock:
            entry = self._intercept_queue.pop(key, None)
            if entry is None:
                return None
            return entry[0]

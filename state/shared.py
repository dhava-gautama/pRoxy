from __future__ import annotations

import fnmatch
import json
import logging
import os
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
    SavedCollection,
    SavedSequence,
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

        # Collections
        self._collections_lock = threading.Lock()
        self._collections: dict[str, SavedCollection] = {}

        # Persistence debouncing
        self._persistence_timer: Optional[threading.Timer] = None
        self._persistence_lock = threading.Lock()

        # Sequences (macros)
        self._sequences_lock = threading.Lock()
        self._sequences: dict[str, SavedSequence] = {}

        # WebSocket injection: (flow_id, to_client, content)
        self.ws_inject_queue: queue.Queue[tuple[str, bool, str]] = queue.Queue()

        # Recording sessions for replay system
        self._recording_lock = threading.Lock()
        self._recording_session: Optional[str] = None
        self._recording_domains: list[str] = []
        self._recorded_flows: list[str] = []

        # Reference to proxy addon for WS flow access (set by addon)
        self.proxy_addon = None

        # Persistence. PROXY_STATE_DIR overrides the default (tests set it to a
        # temp dir so the suite never writes to the user's real ~/.pRoxy).
        self._persistence_dir = Path(os.environ.get("PROXY_STATE_DIR") or (Path.home() / ".pRoxy"))
        self._load_persisted()

    # ── Persistence ─────────────────────────────────────────

    @staticmethod
    def _atomic_write_text(path: Path, text: str) -> None:
        """Write text to `path` atomically.

        write_text() truncates then writes, so a crash mid-write leaves a
        corrupt/empty JSON that _load_persisted then fails to parse. Writing to
        a temp file in the same dir and os.replace()-ing it into place makes the
        update atomic: readers see either the old file or the fully-written new
        one, never a partial.
        """
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, path)

    def _persist_settings(self) -> None:
        # Serialize under the lock so the snapshot is consistent with a
        # concurrent update_settings() replacing self._settings.
        with self._settings_lock:
            text = self._settings.model_dump_json(indent=2)
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "settings.json"
            self._atomic_write_text(path, text)
        except Exception as e:
            _logger.warning("Failed to persist settings: %s", e)

    def _persist_dns(self) -> None:
        # Serialize under the lock so the snapshot is consistent with a
        # concurrent update_dns() replacing self._dns.
        with self._dns_lock:
            text = self._dns.model_dump_json(indent=2)
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "dns.json"
            self._atomic_write_text(path, text)
        except Exception as e:
            _logger.warning("Failed to persist DNS: %s", e)

    def _persist_sequences(self) -> None:
        # Snapshot the dict's values while holding the lock so the debounced
        # timer thread can't iterate while save/delete mutates the dict
        # ("dictionary changed size during iteration"); write to disk outside.
        with self._sequences_lock:
            data = [s.model_dump() for s in self._sequences.values()]
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "sequences.json"
            self._atomic_write_text(path, json.dumps(data, indent=2))
        except Exception as e:
            _logger.warning("Failed to persist sequences: %s", e)

    def _persist_collections(self) -> None:
        # Snapshot the dict's values while holding the lock so the debounced
        # timer thread can't iterate while save/delete mutates the dict
        # ("dictionary changed size during iteration"); write to disk outside.
        with self._collections_lock:
            data = [c.model_dump() for c in self._collections.values()]
        try:
            self._persistence_dir.mkdir(parents=True, exist_ok=True)
            path = self._persistence_dir / "collections.json"
            self._atomic_write_text(path, json.dumps(data, indent=2))
        except Exception as e:
            _logger.warning("Failed to persist collections: %s", e)

    def _debounced_persist(self) -> None:
        """Schedule debounced persistence to reduce I/O overhead."""
        with self._persistence_lock:
            if self._persistence_timer:
                self._persistence_timer.cancel()

            def _do_persist():
                self._persist_settings()
                self._persist_dns()
                self._persist_collections()
                self._persist_sequences()

            self._persistence_timer = threading.Timer(2.0, _do_persist)
            self._persistence_timer.start()

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
        try:
            path = self._persistence_dir / "collections.json"
            if path.exists():
                data = json.loads(path.read_text())
                # Parse fully into a temp dict first, then assign atomically: a
                # bad entry aborts the load and leaves prior in-memory state
                # untouched instead of leaving a silently partial dict.
                parsed: dict[str, SavedCollection] = {}
                for c in data:
                    col = SavedCollection(**c)
                    parsed[col.id] = col
                self._collections = parsed
                _logger.info("Loaded %d persisted collections", len(self._collections))
        except Exception as e:
            _logger.warning("Failed to load persisted collections: %s", e)
        try:
            path = self._persistence_dir / "sequences.json"
            if path.exists():
                data = json.loads(path.read_text())
                # Parse fully into a temp dict first, then assign atomically (see
                # collections above) so a bad entry doesn't partially load.
                parsed_seq: dict[str, SavedSequence] = {}
                for s in data:
                    seq = SavedSequence(**s)
                    parsed_seq[seq.id] = seq
                self._sequences = parsed_seq
                _logger.info("Loaded %d persisted sequences", len(self._sequences))
        except Exception as e:
            _logger.warning("Failed to load persisted sequences: %s", e)

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
        # Copy UNDER the lock so we don't race the mitmproxy thread, which appends
        # to a stored record's mutable lists (ws_messages, grpc/sse/graphql) — also
        # under _flows_lock. Only those lists are replaced (shallow copy shares the
        # immutable body/header fields), so this stays cheap even at large limits.
        with self._flows_lock:
            items = list(self._flows.values())
            items.reverse()
            return [
                f.model_copy(update={
                    "ws_messages": list(f.ws_messages),
                    "grpc_messages": list(f.grpc_messages),
                    "sse_messages": list(f.sse_messages),
                    "graphql_operations": list(f.graphql_operations),
                })
                for f in items[offset : offset + limit]
            ]

    def get_flows_lite(self, limit: int = 200, offset: int = 0) -> list[dict]:
        """Return flows without large body fields for faster list loading."""
        # Serialize UNDER the lock: model_dump walks the record's mutable fields
        # (grpc/sse/graphql lists, headers) which the mitmproxy thread mutates under
        # _flows_lock, so dumping outside it can read a torn snapshot. Mirrors get_flows.
        with self._flows_lock:
            items = list(self._flows.values())
            items.reverse()
            result = []
            for f in items[offset : offset + limit]:
                d = f.model_dump(exclude={"request_body", "response_body", "ws_messages"})
                d["response_size"] = f.response_size or len(f.response_body)
                result.append(d)
        return result

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
            # Snapshot the live list: the mitmproxy thread appends to ws_messages
            # of active WebSocket flows, which would otherwise raise "list
            # changed size during iteration" here.
            for msg in list(f.ws_messages):
                searchable += f" {msg.content}"
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
            self._debounced_persist()
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
            self._debounced_persist()
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

    # ── Collections ────────────────────────────────────────────

    def get_collections(self) -> list[SavedCollection]:
        with self._collections_lock:
            return list(self._collections.values())

    def get_collection(self, collection_id: str) -> Optional[SavedCollection]:
        with self._collections_lock:
            return self._collections.get(collection_id)

    def save_collection(self, collection: SavedCollection) -> SavedCollection:
        with self._collections_lock:
            self._collections[collection.id] = collection
            self._debounced_persist()
            return collection

    def delete_collection(self, collection_id: str) -> bool:
        with self._collections_lock:
            removed = self._collections.pop(collection_id, None) is not None
            if removed:
                self._debounced_persist()
            return removed

    # ── Sequences ──────────────────────────────────────────────

    def get_sequences(self) -> list[SavedSequence]:
        with self._sequences_lock:
            return list(self._sequences.values())

    def get_sequence(self, seq_id: str) -> Optional[SavedSequence]:
        with self._sequences_lock:
            return self._sequences.get(seq_id)

    def save_sequence(self, seq: SavedSequence) -> SavedSequence:
        with self._sequences_lock:
            self._sequences[seq.id] = seq
            self._debounced_persist()
            return seq

    def delete_sequence(self, seq_id: str) -> bool:
        with self._sequences_lock:
            removed = self._sequences.pop(seq_id, None) is not None
            if removed:
                self._debounced_persist()
            return removed

    # ── Recording Sessions ────────────────────────────────────

    def set_recording_session(self, session_id: str, filter_domains: Optional[list[str]] = None) -> None:
        """Start recording traffic to a session."""
        with self._recording_lock:
            self._recording_session = session_id
            self._recording_domains = filter_domains or []
            self._recorded_flows = []

    def stop_recording_session(self, session_id: str) -> list[str]:
        """Stop recording and return recorded flow IDs."""
        with self._recording_lock:
            if self._recording_session == session_id:
                flows = self._recorded_flows.copy()
                self._recording_session = None
                self._recording_domains = []
                self._recorded_flows = []
                return flows
            return []

    def is_recording(self) -> bool:
        """Check if currently recording."""
        with self._recording_lock:
            return self._recording_session is not None

    def should_record_flow(self, host: str) -> bool:
        """Check if flow should be recorded."""
        with self._recording_lock:
            if self._recording_session is None:
                return False
            if not self._recording_domains:  # Record all if no filter
                return True
            return host in self._recording_domains

    def record_flow(self, flow_id: str, host: str) -> None:
        """Record a flow if recording is active."""
        with self._recording_lock:
            if self._recording_session is None:
                return
            # Inline of should_record_flow(): _recording_lock is a non-reentrant
            # Lock, so calling that method here would deadlock the proxy thread.
            if not self._recording_domains or host in self._recording_domains:
                self._recorded_flows.append(flow_id)

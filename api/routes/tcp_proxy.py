"""TCP/UDP proxying for non-HTTP protocols."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, model_validator

from state.shared import ProxyState

router = APIRouter(prefix="/api/tcp", tags=["tcp-proxy"])


class TCPRule(BaseModel):
    """Rule for TCP/UDP proxying."""
    id: str
    name: str
    enabled: bool = True
    protocol: str = "tcp"  # tcp, udp
    listen_port: int
    target_host: str
    target_port: int
    description: str = ""
    log_traffic: bool = True
    max_connections: int = 100
    timeout: int = 300  # seconds

    @model_validator(mode='after')
    def validate_rule(self) -> 'TCPRule':
        if not self.name.strip():
            raise ValueError("Rule name cannot be empty")
        if self.protocol not in ["tcp", "udp"]:
            raise ValueError("Protocol must be 'tcp' or 'udp'")
        if not (1 <= self.listen_port <= 65535):
            raise ValueError("Listen port must be between 1 and 65535")
        if not (1 <= self.target_port <= 65535):
            raise ValueError("Target port must be between 1 and 65535")
        if not self.target_host.strip():
            raise ValueError("Target host cannot be empty")
        return self


class TCPConnection(BaseModel):
    """Represents an active TCP connection."""
    id: str
    rule_id: str
    client_addr: str
    client_port: int
    target_host: str
    target_port: int
    protocol: str
    started_at: float
    bytes_sent: int = 0
    bytes_received: int = 0
    status: str = "active"  # active, closed, error


class TCPTrafficLog(BaseModel):
    """Log entry for TCP traffic."""
    id: str
    connection_id: str
    timestamp: float
    direction: str  # client_to_server, server_to_client
    data_size: int
    data_preview: str  # First 100 bytes as hex or text


# Global storage
_tcp_rules: Dict[str, TCPRule] = {}
_active_connections: Dict[str, TCPConnection] = {}
_traffic_logs: List[TCPTrafficLog] = []


@router.get("/rules")
def list_tcp_rules() -> List[TCPRule]:
    """List all TCP proxy rules."""
    return list(_tcp_rules.values())


@router.post("/rules")
def create_tcp_rule(rule: TCPRule) -> TCPRule:
    """Create TCP proxy rule."""
    rule_id = f"tcp_rule_{int(time.time() * 1000)}"
    rule.id = rule_id

    # Check for port conflicts
    for existing_rule in _tcp_rules.values():
        if existing_rule.enabled and existing_rule.listen_port == rule.listen_port:
            raise HTTPException(400, f"Port {rule.listen_port} already in use by rule '{existing_rule.name}'")

    _tcp_rules[rule_id] = rule

    # Start TCP proxy server for this rule
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.start_tcp_proxy(rule)

    return rule


@router.put("/rules/{rule_id}")
def update_tcp_rule(rule_id: str, rule: TCPRule) -> TCPRule:
    """Update TCP proxy rule."""
    if rule_id not in _tcp_rules:
        raise HTTPException(404, "Rule not found")

    old_rule = _tcp_rules[rule_id]
    rule.id = rule_id

    # Stop old proxy if port changed or disabled
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        if old_rule.enabled:
            state.proxy_addon.stop_tcp_proxy(rule_id)

        # Start new proxy if enabled
        if rule.enabled:
            state.proxy_addon.start_tcp_proxy(rule)

    _tcp_rules[rule_id] = rule
    return rule


@router.delete("/rules/{rule_id}")
def delete_tcp_rule(rule_id: str) -> dict:
    """Delete TCP proxy rule."""
    if rule_id not in _tcp_rules:
        raise HTTPException(404, "Rule not found")

    rule = _tcp_rules[rule_id]

    # Stop proxy server
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None and rule.enabled:
        state.proxy_addon.stop_tcp_proxy(rule_id)

    del _tcp_rules[rule_id]
    return {"message": "Rule deleted"}


@router.post("/rules/{rule_id}/toggle")
def toggle_tcp_rule(rule_id: str) -> TCPRule:
    """Toggle TCP proxy rule enabled state."""
    if rule_id not in _tcp_rules:
        raise HTTPException(404, "Rule not found")

    rule = _tcp_rules[rule_id]
    rule.enabled = not rule.enabled

    # Start/stop proxy server
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        if rule.enabled:
            state.proxy_addon.start_tcp_proxy(rule)
        else:
            state.proxy_addon.stop_tcp_proxy(rule_id)

    return rule


@router.get("/connections")
def list_tcp_connections() -> List[TCPConnection]:
    """List active TCP connections."""
    return list(_active_connections.values())


@router.post("/connections/{connection_id}/close")
def close_tcp_connection(connection_id: str) -> dict:
    """Close TCP connection."""
    if connection_id not in _active_connections:
        raise HTTPException(404, "Connection not found")

    # Close connection via proxy addon
    state = ProxyState()
    if getattr(state, 'proxy_addon', None) is not None:
        state.proxy_addon.close_tcp_connection(connection_id)

    return {"message": "Connection closed"}


@router.get("/traffic")
def get_tcp_traffic(connection_id: Optional[str] = None, limit: int = 1000) -> List[TCPTrafficLog]:
    """Get TCP traffic logs."""
    logs = _traffic_logs

    if connection_id:
        logs = [log for log in logs if log.connection_id == connection_id]

    return logs[-limit:]


@router.delete("/traffic")
def clear_tcp_traffic() -> dict:
    """Clear TCP traffic logs."""
    global _traffic_logs
    _traffic_logs = []
    return {"message": "Traffic logs cleared"}


@router.get("/stats")
def get_tcp_stats() -> dict:
    """Get TCP proxy statistics."""
    stats = {
        "total_rules": len(_tcp_rules),
        "active_rules": len([r for r in _tcp_rules.values() if r.enabled]),
        "active_connections": len(_active_connections),
        "total_traffic_logs": len(_traffic_logs),
        "protocols": {},
        "ports": []
    }

    # Protocol breakdown
    for rule in _tcp_rules.values():
        if rule.enabled:
            stats["protocols"][rule.protocol] = stats["protocols"].get(rule.protocol, 0) + 1
            stats["ports"].append({
                "port": rule.listen_port,
                "protocol": rule.protocol,
                "target": f"{rule.target_host}:{rule.target_port}",
                "name": rule.name
            })

    return stats


# Helper functions for addon integration

def add_tcp_connection(connection: TCPConnection) -> None:
    """Add active TCP connection."""
    _active_connections[connection.id] = connection


def remove_tcp_connection(connection_id: str) -> None:
    """Remove TCP connection."""
    _active_connections.pop(connection_id, None)


def log_tcp_traffic(log_entry: TCPTrafficLog) -> None:
    """Log TCP traffic."""
    _traffic_logs.append(log_entry)

    # Keep only last 10000 logs
    if len(_traffic_logs) > 10000:
        _traffic_logs[:] = _traffic_logs[-5000:]


def get_tcp_rules() -> Dict[str, TCPRule]:
    """Get all TCP rules for addon access."""
    return _tcp_rules
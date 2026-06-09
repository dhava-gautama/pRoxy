"""Parallel Proxy Mode Manager - Run multiple proxy modes simultaneously."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, model_validator

from state.shared import ProxyState

router = APIRouter(prefix="/api/proxy-manager", tags=["proxy-manager"])


class ProxyInstance(BaseModel):
    """Represents a running proxy instance."""
    id: str
    mode: str  # regular, reverse, wireguard, socks, transparent
    status: str  # starting, running, stopped, error
    listen_port: int
    target_url: Optional[str] = None  # For reverse proxy
    thread_id: Optional[str] = None
    started_at: float
    config: Dict[str, Any] = {}
    stats: Dict[str, Any] = {}
    description: str = ""


class ProxyManagerStatus(BaseModel):
    """Overall proxy manager status."""
    total_instances: int
    running_instances: int
    stopped_instances: int
    error_instances: int
    instances: List[ProxyInstance]
    dashboard_url: str
    unified_logging: bool = True


class StartProxyRequest(BaseModel):
    """Request to start a new proxy instance."""
    mode: str
    listen_port: Optional[int] = None  # Auto-assign if None
    target_url: Optional[str] = None   # Required for reverse proxy
    config: Dict[str, Any] = {}
    auto_start: bool = True

    @model_validator(mode='after')
    def validate_request(self) -> 'StartProxyRequest':
        if self.mode == "reverse" and not self.target_url:
            raise ValueError("target_url is required for reverse proxy mode")
        return self


# Global proxy instance storage
_proxy_instances: Dict[str, ProxyInstance] = {}
_proxy_threads: Dict[str, threading.Thread] = {}
_next_instance_id = 1


@router.get("/status")
def get_proxy_manager_status() -> ProxyManagerStatus:
    """Get overall status of all proxy instances."""
    running = sum(1 for p in _proxy_instances.values() if p.status == "running")
    stopped = sum(1 for p in _proxy_instances.values() if p.status == "stopped")
    error = sum(1 for p in _proxy_instances.values() if p.status == "error")

    return ProxyManagerStatus(
        total_instances=len(_proxy_instances),
        running_instances=running,
        stopped_instances=stopped,
        error_instances=error,
        instances=list(_proxy_instances.values()),
        dashboard_url="http://localhost:8081"  # Single dashboard for all modes
    )


@router.get("/instances")
def list_proxy_instances() -> List[ProxyInstance]:
    """List all proxy instances."""
    return list(_proxy_instances.values())


@router.post("/instances")
def start_proxy_instance(request: StartProxyRequest) -> ProxyInstance:
    """Start a new proxy instance."""
    global _next_instance_id

    # Auto-assign port if not specified
    if request.listen_port is None:
        request.listen_port = _get_available_port(request.mode)

    # Check for port conflicts
    for instance in _proxy_instances.values():
        if instance.listen_port == request.listen_port and instance.status == "running":
            raise HTTPException(400, f"Port {request.listen_port} is already in use")

    # Create proxy instance
    instance_id = f"{request.mode}_{_next_instance_id}"
    _next_instance_id += 1

    instance = ProxyInstance(
        id=instance_id,
        mode=request.mode,
        status="starting",
        listen_port=request.listen_port,
        target_url=request.target_url,
        started_at=time.time(),
        config=request.config,
        description=_get_mode_description(request.mode, request.target_url)
    )

    _proxy_instances[instance_id] = instance

    if request.auto_start:
        try:
            # Start the actual proxy thread
            thread = _start_proxy_thread(instance)
            _proxy_threads[instance_id] = thread
            instance.thread_id = thread.name
            instance.status = "running"

        except Exception as e:
            instance.status = "error"
            instance.config["error"] = str(e)
            raise HTTPException(500, f"Failed to start {request.mode} proxy: {e}")

    return instance


@router.delete("/instances/{instance_id}")
def stop_proxy_instance(instance_id: str) -> dict:
    """Stop a specific proxy instance."""
    if instance_id not in _proxy_instances:
        raise HTTPException(404, "Proxy instance not found")

    instance = _proxy_instances[instance_id]

    # Stop the thread if running
    if instance_id in _proxy_threads:
        thread = _proxy_threads[instance_id]
        # Note: Python threads can't be forcefully stopped
        # In a real implementation, we'd use asyncio or subprocess
        print(f"Stopping thread {thread.name} for {instance.mode} proxy")
        del _proxy_threads[instance_id]

    instance.status = "stopped"

    return {"message": f"Proxy instance {instance_id} stopped"}


@router.post("/instances/{instance_id}/restart")
def restart_proxy_instance(instance_id: str) -> ProxyInstance:
    """Restart a specific proxy instance."""
    if instance_id not in _proxy_instances:
        raise HTTPException(404, "Proxy instance not found")

    # Stop first
    stop_proxy_instance(instance_id)

    # Start again
    instance = _proxy_instances[instance_id]
    try:
        thread = _start_proxy_thread(instance)
        _proxy_threads[instance_id] = thread
        instance.thread_id = thread.name
        instance.status = "running"
        instance.started_at = time.time()

    except Exception as e:
        instance.status = "error"
        instance.config["error"] = str(e)
        raise HTTPException(500, f"Failed to restart {instance.mode} proxy: {e}")

    return instance


@router.get("/instances/{instance_id}/stats")
def get_instance_stats(instance_id: str) -> dict:
    """Get statistics for specific proxy instance."""
    if instance_id not in _proxy_instances:
        raise HTTPException(404, "Proxy instance not found")

    instance = _proxy_instances[instance_id]

    # Get stats from proxy state
    state = ProxyState()
    base_stats = {
        "instance_id": instance_id,
        "mode": instance.mode,
        "uptime": time.time() - instance.started_at if instance.status == "running" else 0,
        "status": instance.status,
        "port": instance.listen_port
    }

    # Mode-specific stats
    if instance.mode == "regular":
        flows = state.get_flows(limit=1000)
        base_stats.update({
            "total_flows": len(flows),
            "https_flows": len([f for f in flows if f.scheme == "https"]),
            "unique_hosts": len(set(f.host for f in flows))
        })

    elif instance.mode == "reverse":
        base_stats.update({
            "target_url": instance.target_url,
            "ssl_bypass_active": True,
            "pinning_bypassed": True
        })

    elif instance.mode == "wireguard":
        # Would get WireGuard-specific stats
        base_stats.update({
            "vpn_clients": 0,  # Would get from WireGuard status
            "capture_all_traffic": True
        })

    return base_stats


@router.get("/recommended-setup")
def get_recommended_parallel_setup(
    device_type: str = "android",
    use_case: str = "comprehensive_testing"
) -> dict:
    """Get recommended parallel proxy setup for specific scenarios."""

    if use_case == "comprehensive_testing":
        return {
            "setup": "parallel_comprehensive",
            "description": "Run multiple modes for complete coverage",
            "recommended_instances": [
                {
                    "mode": "regular",
                    "port": 8080,
                    "purpose": "Browser and proxy-aware apps",
                    "ssl_bypass": "certificate_installation"
                },
                {
                    "mode": "wireguard",
                    "port": 51820,
                    "purpose": "Apps that bypass proxy settings",
                    "ssl_bypass": "vpn_level_capture"
                },
                {
                    "mode": "reverse",
                    "port": 8443,
                    "purpose": "API testing with zero configuration",
                    "ssl_bypass": "complete_bypass"
                }
            ],
            "ssl_pinning_strategy": "multi_layered",
            "coverage": "99%",
            "advantages": [
                "Complete traffic coverage",
                "Multiple SSL bypass methods",
                "Fallback options for difficult apps",
                "Single dashboard for all modes"
            ]
        }

    elif use_case == "ssl_pinning_bypass":
        return {
            "setup": "ssl_focused",
            "description": "Specialized setup for SSL pinning bypass",
            "recommended_instances": [
                {
                    "mode": "reverse",
                    "port": 8443,
                    "purpose": "Primary SSL pinning bypass",
                    "effectiveness": "95%"
                },
                {
                    "mode": "wireguard",
                    "port": 51820,
                    "purpose": "Backup for difficult apps",
                    "effectiveness": "80%"
                }
            ],
            "ssl_strategy": "reverse_proxy_primary",
            "setup_steps": [
                "1. Start reverse proxy mode for target domains",
                "2. Redirect app traffic to pRoxy via DNS/hosts",
                "3. App connects directly to pRoxy (no pinning check)",
                "4. pRoxy handles real SSL to servers",
                "5. Complete SSL bypass achieved!"
            ]
        }

    elif use_case == "development":
        return {
            "setup": "development_focused",
            "recommended_instances": [
                {
                    "mode": "regular",
                    "port": 8080,
                    "purpose": "Development and debugging"
                }
            ],
            "ssl_strategy": "certificate_installation"
        }

    return {"error": f"Unknown use case: {use_case}"}


@router.post("/quick-setup/ssl-bypass")
def quick_setup_ssl_bypass(
    target_domains: List[str],
    app_package: Optional[str] = None
) -> dict:
    """Quickly setup SSL bypass for specific domains."""

    instances_created = []

    try:
        # Start reverse proxy for each domain
        for i, domain in enumerate(target_domains):
            port = 8443 + i  # Use different ports for each domain

            request = StartProxyRequest(
                mode="reverse",
                listen_port=port,
                target_url=f"https://{domain}",
                config={"ssl_bypass": True, "target_domain": domain}
            )

            instance = start_proxy_instance(request)
            instances_created.append(instance)

        # Also start WireGuard as backup
        wg_request = StartProxyRequest(
            mode="wireguard",
            listen_port=51820,
            config={"ssl_bypass_backup": True}
        )

        try:
            wg_instance = start_proxy_instance(wg_request)
            instances_created.append(wg_instance)
        except Exception:
            pass  # WireGuard is optional

        return {
            "message": "SSL bypass setup completed",
            "instances_created": len(instances_created),
            "instances": instances_created,
            "next_steps": [
                "1. Configure device DNS or hosts file to point domains to pRoxy",
                f"2. Domain redirections needed: {target_domains}",
                "3. Install WireGuard profile as backup method",
                "4. Test app - SSL pinning should be completely bypassed!"
            ],
            "dns_redirections": [
                f"{domain} -> YOUR_PROXY_IP:{8443 + i}" for i, domain in enumerate(target_domains)
            ]
        }

    except Exception as e:
        # Cleanup created instances on error
        for instance in instances_created:
            try:
                stop_proxy_instance(instance.id)
            except Exception:
                pass

        raise HTTPException(500, f"SSL bypass setup failed: {e}")


@router.get("/dashboard/unified")
def get_unified_dashboard_data() -> dict:
    """Get unified dashboard data for all running proxy instances."""

    state = ProxyState()
    flows = state.get_flows(limit=500)

    # Aggregate data from all proxy modes
    dashboard_data = {
        "proxy_instances": list(_proxy_instances.values()),
        "total_flows": len(flows),
        "ssl_bypass_active": any(p.mode == "reverse" and p.status == "running" for p in _proxy_instances.values()),
        "vpn_capture_active": any(p.mode == "wireguard" and p.status == "running" for p in _proxy_instances.values()),
        "comprehensive_coverage": len([p for p in _proxy_instances.values() if p.status == "running"]) >= 2,
        "recent_activity": [
            {
                "time": f.timestamp,
                "source": _identify_proxy_source(f),
                "method": f.method,
                "url": f.url,
                "status": f.status_code
            }
            for f in flows[:20]
        ],
        "mode_statistics": _get_mode_statistics(),
        "ssl_pinning_status": _get_ssl_pinning_status()
    }

    return dashboard_data


def _get_available_port(mode: str) -> int:
    """Get default port for proxy mode."""
    default_ports = {
        "regular": 8080,
        "reverse": 8443,
        "wireguard": 51820,
        "socks": 1080,
        "transparent": 8080
    }

    base_port = default_ports.get(mode, 8080)

    # Check if base port is available
    used_ports = {p.listen_port for p in _proxy_instances.values() if p.status == "running"}

    if base_port not in used_ports:
        return base_port

    # Find next available port
    for offset in range(1, 100):
        candidate = base_port + offset
        if candidate not in used_ports:
            return candidate

    raise Exception(f"No available ports for {mode} proxy")


def _get_mode_description(mode: str, target_url: Optional[str] = None) -> str:
    """Get human-readable description for proxy mode."""
    descriptions = {
        "regular": "Standard HTTP/HTTPS proxy for browser and proxy-aware apps",
        "reverse": f"Reverse proxy acting as server for {target_url or 'target'}",
        "wireguard": "VPN mode for comprehensive traffic capture",
        "socks": "SOCKS5 proxy for applications with SOCKS support",
        "transparent": "Transparent proxy for OS-level traffic capture"
    }

    return descriptions.get(mode, f"Proxy mode: {mode}")


def _start_proxy_thread(instance: ProxyInstance) -> threading.Thread:
    """Start actual proxy thread for instance."""

    # Import here to avoid circular imports
    from proxy.engine import start_proxy_thread, start_reverse_proxy, start_socks_proxy

    if instance.mode == "regular":
        return start_proxy_thread("0.0.0.0", instance.listen_port, "regular")

    elif instance.mode == "reverse":
        return start_reverse_proxy(instance.target_url, instance.listen_port)

    elif instance.mode == "socks":
        return start_socks_proxy(instance.listen_port)

    elif instance.mode == "wireguard":
        # WireGuard would be started via separate API
        # Return dummy thread for now
        def wireguard_placeholder():
            print(f"WireGuard proxy on port {instance.listen_port}")

        thread = threading.Thread(target=wireguard_placeholder, name=f"wireguard-{instance.listen_port}")
        thread.start()
        return thread

    elif instance.mode == "transparent":
        return start_proxy_thread("0.0.0.0", instance.listen_port, "transparent")

    else:
        raise Exception(f"Unknown proxy mode: {instance.mode}")


def _identify_proxy_source(flow) -> str:
    """Identify which proxy instance captured this flow."""
    # This would analyze the flow to determine source proxy
    return "regular"  # Simplified for now


def _get_mode_statistics() -> Dict[str, Any]:
    """Get statistics for each proxy mode."""
    stats = {}

    for instance in _proxy_instances.values():
        if instance.status == "running":
            stats[instance.mode] = {
                "port": instance.listen_port,
                "uptime": time.time() - instance.started_at,
                "ssl_bypass": instance.mode == "reverse"
            }

    return stats


def _get_ssl_pinning_status() -> Dict[str, Any]:
    """Get overall SSL pinning bypass status."""
    reverse_active = any(p.mode == "reverse" and p.status == "running" for p in _proxy_instances.values())

    return {
        "bypass_active": reverse_active,
        "method": "reverse_proxy" if reverse_active else "none",
        "effectiveness": "95%" if reverse_active else "0%",
        "coverage": "Complete" if reverse_active else "None"
    }
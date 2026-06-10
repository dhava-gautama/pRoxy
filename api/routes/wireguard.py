"""WireGuard VPN mode for capturing mobile device traffic without root."""

from __future__ import annotations

import base64
import ipaddress
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, model_validator

from state.shared import ProxyState

router = APIRouter(prefix="/api/wireguard", tags=["wireguard"])


class WireGuardConfig(BaseModel):
    """WireGuard VPN configuration."""
    enabled: bool = False
    interface_name: str = "wg-prxy"
    listen_port: int = 51820
    server_ip: str = "10.0.0.1"
    client_ip_range: str = "10.0.0.0/24"
    dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
    allowed_ips: List[str] = ["0.0.0.0/0"]  # Route all traffic
    server_private_key: str = ""
    server_public_key: str = ""
    mtu: int = 1420

    @model_validator(mode='after')
    def validate_config(self) -> 'WireGuardConfig':
        try:
            ipaddress.ip_network(self.client_ip_range)
            ipaddress.ip_address(self.server_ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP configuration: {e}")
        return self


class WireGuardClient(BaseModel):
    """WireGuard client configuration."""
    id: str
    name: str
    ip_address: str
    private_key: str
    public_key: str
    created_at: float
    last_seen: Optional[float] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    status: str = "inactive"  # inactive, active, connecting


class WireGuardStats(BaseModel):
    """WireGuard connection statistics."""
    interface_status: str
    connected_clients: int
    total_clients: int
    bytes_sent: int
    bytes_received: int
    uptime: int


# Global storage
_wg_config = WireGuardConfig()
_wg_clients: Dict[str, WireGuardClient] = {}

def _is_wireguard_running() -> bool:
    """Check whether the mitmproxy WireGuard proxy is listening.

    mitmproxy implements WireGuard in userspace, so there is no kernel `wg-prxy`
    interface to find with `ip link` (the old check always returned False even
    when the proxy was up). Instead, detect it by whether the UDP listen port is
    already bound — if we can't bind it, the WireGuard proxy has it.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", _wg_config.listen_port))
        return False  # port is free → not running
    except OSError:
        return True   # port already bound → the WireGuard proxy is up
    finally:
        s.close()


@router.get("/config")
def get_wireguard_config() -> WireGuardConfig:
    """Get WireGuard configuration."""
    return _wg_config


@router.post("/config")
def update_wireguard_config(config: WireGuardConfig) -> WireGuardConfig:
    """Update WireGuard configuration."""
    global _wg_config

    # Generate keys if not provided
    if not config.server_private_key or not config.server_public_key:
        private_key, public_key = _generate_keypair()
        config.server_private_key = private_key
        config.server_public_key = public_key

    _wg_config = config
    return _wg_config


@router.post("/start")
def start_wireguard() -> dict:
    """Start WireGuard VPN server."""
    # Note: mitmproxy WireGuard instance starts automatically in dual mode
    # This endpoint is mainly for configuration initialization

    if _is_wireguard_running():
        # Auto-initialize configuration if not set up
        if not _wg_config.server_private_key:
            private_key, public_key = _generate_keypair()
            _wg_config.server_private_key = private_key
            _wg_config.server_public_key = public_key

        return {"message": "WireGuard VPN is running", "listen_port": _wg_config.listen_port}
    else:
        raise HTTPException(500, "WireGuard VPN is not available (check main process)")


@router.post("/stop")
def stop_wireguard() -> dict:
    """Stop WireGuard VPN server."""
    # Note: We can't actually stop the mitmproxy WireGuard instance from here
    # since it's managed by the main proxy engine and runs in dual mode
    raise HTTPException(400, "WireGuard VPN cannot be stopped individually - it's part of dual mode operation")


@router.get("/status")
def get_wireguard_status() -> dict:
    """Get WireGuard server status."""
    running = _is_wireguard_running()
    return {
        "running": running,
        "interface": _wg_config.interface_name,
        "listen_port": _wg_config.listen_port,
        "server_ip": _wg_config.server_ip,
        "connected_clients": len([c for c in _wg_clients.values() if c.status == "active"])
    }


@router.get("/clients")
def list_wireguard_clients() -> List[WireGuardClient]:
    """List WireGuard clients."""
    return list(_wg_clients.values())


class CreateClientRequest(BaseModel):
    name: str
    device_type: str = "mobile"


@router.post("/clients")
def create_wireguard_client(request: CreateClientRequest) -> WireGuardClient:
    """Create new WireGuard client."""
    name = request.name
    device_type = request.device_type
    if len(_wg_clients) >= 50:  # Reasonable limit
        raise HTTPException(400, "Maximum number of clients reached")

    # Generate client IP
    network = ipaddress.ip_network(_wg_config.client_ip_range)
    used_ips = {client.ip_address for client in _wg_clients.values()}
    used_ips.add(_wg_config.server_ip)  # Server IP is also used

    client_ip = None
    for ip in network.hosts():
        if str(ip) not in used_ips:
            client_ip = str(ip)
            break

    if not client_ip:
        raise HTTPException(400, "No available IP addresses in range")

    # Generate client keys
    private_key, public_key = _generate_keypair()

    client = WireGuardClient(
        id=f"client_{int(time.time() * 1000)}",
        name=name,
        ip_address=client_ip,
        private_key=private_key,
        public_key=public_key,
        created_at=time.time()
    )

    _wg_clients[client.id] = client

    # Ensure server keys exist before writing config
    if not _wg_config.server_private_key or not _wg_config.server_public_key:
        private_key_s, public_key_s = _generate_keypair()
        _wg_config.server_private_key = private_key_s
        _wg_config.server_public_key = public_key_s

    # Update WireGuard config if running
    if _is_wireguard_running():
        _update_wireguard_config()

    return client


@router.delete("/clients/{client_id}")
def delete_wireguard_client(client_id: str) -> dict:
    """Delete WireGuard client."""
    if client_id not in _wg_clients:
        raise HTTPException(404, "Client not found")

    del _wg_clients[client_id]

    # Update WireGuard config if running
    if _is_wireguard_running():
        _update_wireguard_config()

    return {"message": "Client deleted"}


@router.get("/clients/{client_id}/config")
def get_client_config(client_id: str, format: str = "qr") -> dict:
    """Get client configuration for mobile setup."""
    if client_id not in _wg_clients:
        raise HTTPException(404, "Client not found")

    client = _wg_clients[client_id]

    # Auto-initialize server keys if not yet generated
    if not _wg_config.server_private_key or not _wg_config.server_public_key:
        private_key, public_key = _generate_keypair()
        _wg_config.server_private_key = private_key
        _wg_config.server_public_key = public_key

    # Generate client config file
    server_endpoint = _get_server_endpoint()
    config_text = _generate_client_config(client)

    base_response = {
        "config_text": config_text,
        "client_ip": client.ip_address,
        "server_endpoint": f"{server_endpoint}:{_wg_config.listen_port}",
        "client_name": client.name,
    }

    if format == "qr":
        qr_code = _generate_qr_code(config_text)
        return {
            **base_response,
            "qr_code": qr_code,
            "instructions": _get_mobile_instructions()
        }
    else:
        return base_response


@router.get("/stats")
def get_wireguard_stats() -> WireGuardStats:
    """Get WireGuard connection statistics."""
    if not _is_wireguard_running():
        return WireGuardStats(
            interface_status="down",
            connected_clients=0,
            total_clients=len(_wg_clients),
            bytes_sent=0,
            bytes_received=0,
            uptime=0
        )

    # Parse wg show output for real stats
    stats = _parse_wireguard_stats()

    return WireGuardStats(
        interface_status="up",
        connected_clients=stats.get("connected_clients", 0),
        total_clients=len(_wg_clients),
        bytes_sent=stats.get("bytes_sent", 0),
        bytes_received=stats.get("bytes_received", 0),
        uptime=stats.get("uptime", 0)
    )


# Helper functions

def _generate_keypair() -> tuple[str, str]:
    """Generate WireGuard private/public key pair."""
    try:
        # Generate private key
        private_key = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        # Generate public key from private
        public_key = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        return private_key, public_key

    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to OpenSSL if wg tools not available
        return _generate_keypair_openssl()


def _generate_keypair_openssl() -> tuple[str, str]:
    """Generate keys using OpenSSL as fallback."""
    # Generate random 32 bytes for private key
    import secrets
    private_bytes = secrets.token_bytes(32)
    private_key = base64.b64encode(private_bytes).decode()

    # For demo purposes - in production, implement proper Curve25519
    public_key = base64.b64encode(secrets.token_bytes(32)).decode()

    return private_key, public_key


def _setup_wireguard_interface() -> None:
    """Setup WireGuard network interface."""
    try:
        # Create interface
        subprocess.run([
            "ip", "link", "add", "dev", _wg_config.interface_name, "type", "wireguard"
        ], check=True)

        # Set IP address
        subprocess.run([
            "ip", "address", "add", f"{_wg_config.server_ip}/24",
            "dev", _wg_config.interface_name
        ], check=True)

        # Bring interface up
        subprocess.run([
            "ip", "link", "set", "up", "dev", _wg_config.interface_name
        ], check=True)

    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to setup interface: {e}")


def _start_wireguard_daemon() -> None:
    """Start WireGuard daemon with configuration."""
    # Create config file
    config_path = Path(f"/tmp/{_wg_config.interface_name}.conf")
    config_content = _generate_server_config()
    config_path.write_text(config_content)

    try:
        # Set WireGuard configuration
        subprocess.run([
            "wg", "setconf", _wg_config.interface_name, str(config_path)
        ], check=True)

    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to start WireGuard: {e}")
    finally:
        # Clean up config file
        config_path.unlink(missing_ok=True)


def _setup_traffic_routing() -> None:
    """Setup traffic routing to proxy through mitmproxy."""
    try:
        # Enable IP forwarding
        subprocess.run([
            "sysctl", "-w", "net.ipv4.ip_forward=1"
        ], check=True)

        # Add iptables rules to route traffic through mitmproxy
        # Traffic from WireGuard clients → transparent proxy
        subprocess.run([
            "iptables", "-t", "mangle", "-A", "PREROUTING",
            "-i", _wg_config.interface_name,
            "-p", "tcp", "--dport", "80",
            "-j", "MARK", "--set-mark", "1"
        ], check=True)

        subprocess.run([
            "iptables", "-t", "mangle", "-A", "PREROUTING",
            "-i", _wg_config.interface_name,
            "-p", "tcp", "--dport", "443",
            "-j", "MARK", "--set-mark", "1"
        ], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to setup routing: {e}")


def _stop_wireguard_daemon() -> None:
    """Stop WireGuard daemon."""
    try:
        subprocess.run(["wg-quick", "down", _wg_config.interface_name], check=False)
    except subprocess.CalledProcessError:
        pass  # Interface may not exist


def _cleanup_wireguard_interface() -> None:
    """Cleanup WireGuard interface."""
    try:
        subprocess.run(["ip", "link", "delete", _wg_config.interface_name], check=False)
    except subprocess.CalledProcessError:
        pass  # Interface may not exist


def _update_wireguard_config() -> None:
    """Update running WireGuard configuration."""
    if not _is_wireguard_running():
        return

    try:
        # Regenerate and apply config
        config_path = Path(f"/tmp/{_wg_config.interface_name}.conf")
        config_content = _generate_server_config()
        config_path.write_text(config_content)

        subprocess.run([
            "wg", "setconf", _wg_config.interface_name, str(config_path)
        ], check=True)

        config_path.unlink(missing_ok=True)

    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to update WireGuard config: {e}")


def _generate_server_config() -> str:
    """Generate WireGuard server configuration."""
    config = [
        "[Interface]",
        f"PrivateKey = {_wg_config.server_private_key}",
        f"Address = {_wg_config.server_ip}/24",
        f"ListenPort = {_wg_config.listen_port}",
        "SaveConfig = true",
        ""
    ]

    # Add each client as a peer
    for client in _wg_clients.values():
        config.extend([
            "[Peer]",
            f"PublicKey = {client.public_key}",
            f"AllowedIPs = {client.ip_address}/32",
            ""
        ])

    return "\n".join(config)


def _generate_client_config(client: WireGuardClient) -> str:
    """Generate client configuration file."""
    # Try to detect server IP automatically
    server_endpoint = _get_server_endpoint()

    return f"""[Interface]
PrivateKey = {client.private_key}
Address = {client.ip_address}/24
DNS = {', '.join(_wg_config.dns_servers)}
MTU = {_wg_config.mtu}

[Peer]
PublicKey = {_wg_config.server_public_key}
Endpoint = {server_endpoint}:{_wg_config.listen_port}
AllowedIPs = {', '.join(_wg_config.allowed_ips)}
PersistentKeepalive = 25"""


def _generate_qr_code(config_text: str) -> Optional[str]:
    """Generate QR code for mobile WireGuard app."""
    try:
        import qrcode
        from io import BytesIO

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(config_text)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_data = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_data}"

    except ImportError:
        return None


def _get_mobile_instructions() -> List[str]:
    """Get setup instructions for mobile devices."""
    return [
        "1. Install WireGuard app from App Store/Google Play",
        "2. Tap '+' to add new tunnel",
        "3. Choose 'Scan QR code' or paste config text",
        "4. Enable the tunnel connection",
        "5. All traffic will now go through pRoxy for analysis",
        "6. Install pRoxy CA certificate if needed for HTTPS"
    ]


def _parse_wireguard_stats() -> dict:
    """Parse WireGuard statistics from system."""
    try:
        result = subprocess.run([
            "wg", "show", _wg_config.interface_name, "dump"
        ], capture_output=True, text=True, check=True)

        # Parse the output to get real statistics
        lines = result.stdout.strip().split('\n')
        stats = {"connected_clients": 0, "bytes_sent": 0, "bytes_received": 0}

        for line in lines[1:]:  # Skip header
            if line.strip():
                stats["connected_clients"] += 1
                # Parse bytes from line (simplified)
                parts = line.split('\t')
                if len(parts) >= 6:
                    try:
                        stats["bytes_received"] += int(parts[5])
                        stats["bytes_sent"] += int(parts[6])
                    except (ValueError, IndexError):
                        pass

        return stats

    except subprocess.CalledProcessError:
        return {"connected_clients": 0, "bytes_sent": 0, "bytes_received": 0}


def _get_server_endpoint() -> str:
    """Get server endpoint IP for client configuration."""
    import socket

    try:
        # Try to get the default route interface IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to a remote address to determine local IP
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception:
        # Fallback to localhost if detection fails
        return "127.0.0.1"


def is_wireguard_available() -> bool:
    """Check if WireGuard is available on system."""
    try:
        subprocess.run(["wg", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
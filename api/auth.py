#!/usr/bin/env python3

import os
import secrets
from typing import Optional
from pathlib import Path

from fastapi import HTTPException, Request, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Simple authentication for pRoxy dashboard
# Uses API key stored in ~/.pRoxy/auth.key

AUTH_DISABLED = True  # Authentication disabled for local lab setup

security = HTTPBearer(auto_error=False)


def get_auth_key_path() -> Path:
    """Get path to the authentication key file."""
    proxy_dir = Path.home() / ".pRoxy"
    proxy_dir.mkdir(exist_ok=True)
    return proxy_dir / "auth.key"


def get_or_create_auth_key() -> str:
    """Get existing auth key or create a new one."""
    if AUTH_DISABLED:
        return ""

    key_path = get_auth_key_path()

    if key_path.exists():
        try:
            return key_path.read_text().strip()
        except (OSError, IOError):
            pass  # Fall through to generate new key

    # Generate new 32-character key
    new_key = secrets.token_urlsafe(24)
    try:
        key_path.write_text(new_key)
        key_path.chmod(0o600)  # Read/write for owner only
        print(f"[pRoxy.auth] Generated new auth key: {new_key}")
        print(f"[pRoxy.auth] Key saved to: {key_path}")
        print(f"[pRoxy.auth] Add ?key={new_key} to your dashboard URL or use Authorization: Bearer {new_key}")
    except (OSError, IOError) as e:
        print(f"[pRoxy.auth] Warning: Could not save auth key: {e}")

    return new_key


def verify_auth_key(provided_key: str) -> bool:
    """Verify if the provided key matches the stored key."""
    if AUTH_DISABLED:
        return True

    stored_key = get_or_create_auth_key()
    if not stored_key:
        return True  # No auth if key generation failed

    return secrets.compare_digest(provided_key, stored_key)


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None
) -> str:
    """Authenticate user via query param or Authorization header."""
    if AUTH_DISABLED:
        return "anonymous"

    # Check query parameter first (for web dashboard)
    key_from_query = request.query_params.get("key")
    if key_from_query and verify_auth_key(key_from_query):
        return "authenticated"

    # Check Authorization header (for API access)
    if credentials and verify_auth_key(credentials.credentials):
        return "authenticated"

    # No valid authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Check console for key or use ?key=YOUR_KEY in URL.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# Helper function for router dependencies
def create_auth_dependencies():
    """Create auth dependencies list for routers."""
    return [Depends(get_current_user)] if not AUTH_DISABLED else []

# Initialize auth key on module import
_AUTH_KEY = get_or_create_auth_key()
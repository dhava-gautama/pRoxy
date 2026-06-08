#!/usr/bin/env python3

from enum import Enum


class SessionStatus(str, Enum):
    """Session status values."""
    CREATED = "created"
    RECORDING = "recording"
    REPLAYING = "replaying"
    COMPLETED = "completed"
    ERROR = "error"


class FallbackAction(str, Enum):
    """Fallback action for replay rules."""
    PASSTHROUGH = "passthrough"
    BLOCK = "block"
    ERROR = "error"


class FlowType(str, Enum):
    """Flow type classifications."""
    HTTP = "http"
    WEBSOCKET = "websocket"
    TCP = "tcp"


class ProxyMode(str, Enum):
    """Proxy operation modes."""
    REGULAR = "regular"
    TRANSPARENT = "transparent"
    REVERSE = "reverse"
    UPSTREAM = "upstream"
"""Redis pub/sub helpers for pipeline → WebSocket event streaming."""

import json
from datetime import datetime, timezone
from typing import Any

import redis

from core.config import get_settings


def _channel(scan_id: str) -> str:
    return f"scan:{scan_id}:events"


def _redis_client() -> redis.Redis:
    return redis.from_url(get_settings().redis_url, decode_responses=True)


def publish_scan_event(scan_id: str, event_type: str, **payload: Any) -> None:
    """Publish a JSON event to the scan's Redis channel."""
    message = {
        "type": event_type,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    _redis_client().publish(_channel(scan_id), json.dumps(message))


def scan_event_channel(scan_id: str) -> str:
    return _channel(scan_id)

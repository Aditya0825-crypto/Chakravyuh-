"""WebSocket scan event stream backed by Redis pub/sub."""

import asyncio
import json
import uuid

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.config import get_settings
from core.events import scan_event_channel
from db.models import PipelineEvent
from db.session import SessionLocal

router = APIRouter()


@router.websocket("/scans/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    settings = get_settings()

    # Send recent persisted events first
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.send_json({"type": "error", "message": "Invalid scan id"})
        await websocket.close()
        return

    db = SessionLocal()
    try:
        events = (
            db.query(PipelineEvent)
            .filter(PipelineEvent.scan_id == scan_uuid)
            .order_by(PipelineEvent.timestamp.asc())
            .limit(200)
            .all()
        )
        for ev in events:
            await websocket.send_json(
                {
                    "type": "log",
                    "stage": ev.stage,
                    "level": ev.level.value,
                    "message": ev.message,
                    "timestamp": ev.timestamp.isoformat(),
                }
            )
    finally:
        db.close()

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis_client.pubsub()
    channel = scan_event_channel(scan_id)

    try:
        await pubsub.subscribe(channel)
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=1.0
            )
            if message and message.get("type") == "message":
                data = json.loads(message["data"])
                await websocket.send_json(data)
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
        await redis_client.close()

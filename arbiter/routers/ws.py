"""CHAKRAVYUH Arbiter — WebSocket event-stream router.

Provides a ``/ws/events`` endpoint for real-time push notifications.
Connected clients receive JSON messages for every CREP state transition.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("arbiter.ws")

router = APIRouter(tags=["websocket"])

# ── Shared reference (wired at startup from main.py) ─────────────────────────
_ws_manager = None  # type: ignore[assignment]


def init_ws_router(manager) -> None:  # noqa: ANN001
    """Inject the global :class:`ConnectionManager` into this module.

    Called from :func:`main.lifespan`.
    """
    global _ws_manager  # noqa: PLW0603
    _ws_manager = manager


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    """Accept an incoming WebSocket connection and keep it alive.

    The connection is registered with the global
    :class:`ConnectionManager`.  Events are pushed to the client via
    :meth:`ConnectionManager.broadcast` whenever the CREP engine
    transitions a round's state.

    The read loop exists solely to detect client disconnection — the
    server never expects inbound application messages.
    """
    if _ws_manager is None:
        await ws.close(code=1013, reason="Service not ready")
        return

    await _ws_manager.connect(ws)
    try:
        while True:
            # Block until the client sends something (or disconnects).
            # We don't process inbound messages — this just keeps the
            # connection alive and lets FastAPI detect closure.
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_manager.disconnect(ws)
        logger.info("Client disconnected from /ws/events.")
    except Exception:
        _ws_manager.disconnect(ws)


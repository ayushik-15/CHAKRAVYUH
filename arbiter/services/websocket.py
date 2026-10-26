"""CHAKRAVYUH Arbiter — WebSocket connection manager.

Manages a pool of active WebSocket connections and provides a broadcast
primitive so every state-machine transition can be pushed to the frontend
in real time.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("arbiter.websocket")


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages.

    Usage::

        manager = ConnectionManager()
        await manager.connect(ws)         # on new client
        await manager.broadcast(payload)  # after each state change
        manager.disconnect(ws)            # on client disconnect
    """

    def __init__(self) -> None:
        """Initialise an empty list of active WebSocket connections."""
        self._active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        """Accept an incoming WebSocket and register it.

        Args:
            ws: The incoming :class:`WebSocket` connection.
        """
        await ws.accept()
        self._active_connections.append(ws)
        logger.info(
            "WebSocket connected (%d active).", len(self._active_connections),
        )

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket from the active list.

        Safe to call even if the WebSocket is not in the list (e.g. if
        it was already removed after a failed broadcast).

        Args:
            ws: The disconnected :class:`WebSocket`.
        """
        try:
            self._active_connections.remove(ws)
        except ValueError:
            pass
        logger.info(
            "WebSocket disconnected (%d active).", len(self._active_connections),
        )

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a JSON message to every active WebSocket.

        Connections that fail during send are removed silently so a
        single dead client never blocks the rest.

        Args:
            message: JSON-serialisable dict to broadcast.
        """
        stale: list[WebSocket] = []
        for ws in self._active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                # Client probably disconnected — mark for removal
                stale.append(ws)

        for ws in stale:
            self.disconnect(ws)

        if stale:
            logger.debug(
                "Pruned %d stale WebSocket(s) during broadcast.", len(stale),
            )

    @property
    def active_count(self) -> int:
        """Return the number of currently active connections."""
        return len(self._active_connections)


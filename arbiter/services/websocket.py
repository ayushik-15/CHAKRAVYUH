from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("arbiter.websocket")


class ConnectionManager:


    def __init__(self) -> None:
        self._active_connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._active_connections.append(ws)
        logger.info(
            "WebSocket connected (%d active).", len(self._active_connections),
        )

    def disconnect(self, ws: WebSocket) -> None:
        try:
            self._active_connections.remove(ws)
        except ValueError:
            pass
        logger.info(
            "WebSocket disconnected (%d active).", len(self._active_connections),
        )

    async def broadcast(self, message: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for ws in self._active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)

        for ws in stale:
            self.disconnect(ws)

        if stale:
            logger.debug(
                "Pruned %d stale WebSocket(s) during broadcast.", len(stale),
            )

    @property
    def active_count(self) -> int:
        return len(self._active_connections)


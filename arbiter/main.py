"""CHAKRAVYUH Arbiter Hub — FastAPI WebSocket backend.

Streams mock Commit-Reveal Evaluation Protocol events (attack, defense,
verdict) to connected WebSocket clients on a 4-second cycle.
"""

from __future__ import annotations

import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="CHAKRAVYUH Arbiter Hub", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Health check ─────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict:
    """Return service health status for Docker/CI readiness probes."""
    return {"status": "healthy", "service": "arbiter"}


# ── Mock event cycle ────────────────────────────────────────────────────────

MOCK_EVENTS = [
    {
        "type": "attack",
        "plane": "Red Plane",
        "payload": "Red Plane Attack — adversarial prompt injected.",
    },
    {
        "type": "defense",
        "plane": "Blue Plane",
        "payload": "Blue Plane Defense — input sanitised and context isolated.",
    },
    {
        "type": "info",
        "plane": "Arbiter",
        "payload": "Arbiter Verdict — commitment hash verified. Round integrity intact.",
    },
]

# ── WebSocket endpoint ──────────────────────────────────────────────────────


@app.websocket("/ws")
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Accept a WebSocket connection and stream mock CREP events."""
    await websocket.accept()

    # Send the initial system-ready message.
    await websocket.send_json(
        {
            "type": "info",
            "plane": "System Initialized",
            "payload": "Arbiter Hub online. Commencing Commit-Reveal Evaluation Protocol.",
        }
    )

    try:
        idx = 0
        while True:
            await asyncio.sleep(4)
            await websocket.send_json(MOCK_EVENTS[idx % len(MOCK_EVENTS)])
            idx += 1
    except WebSocketDisconnect:
        pass

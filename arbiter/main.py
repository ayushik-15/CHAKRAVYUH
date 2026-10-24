"""CHAKRAVYUH Arbiter — FastAPI application entry-point.

The Arbiter orchestrates the commit → seal → evaluate → reveal pipeline,
verifying integrity via the Merkle-log and coordinating the red, blue, and
LLM planes.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt

from config import settings
from routers.health import router as health_router

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("arbiter")


# ── Application lifespan ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Execute startup / shutdown hooks for the Arbiter service."""
    logger.info("Arbiter service started")
    logger.info(
        "Merkle-log target: %s:%s",
        settings.MERKLE_HOST,
        settings.MERKLE_PORT,
    )
    logger.info("LLM plane target: %s", settings.LLM_PLANE_URL)
    yield
    logger.info("Arbiter service shutting down")


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="CHAKRAVYUH Arbiter",
    description=(
        "Central orchestrator for the CHAKRAVYUH AI-safety evaluation "
        "pipeline.  Manages round lifecycle, commitment verification, "
        "and Merkle-anchored audit trails."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── JWT identity middleware ──────────────────────────────────────────────────

@app.middleware("http")
async def inject_plane_identity(request: Request, call_next):
    """Extract plane identity from a JWT bearer token and inject it into
    ``request.state`` so downstream handlers can authorise per-plane.

    If no ``Authorization`` header is present or the token is invalid, the
    request proceeds without identity — individual endpoints decide whether
    authentication is mandatory.
    """
    auth_header: str | None = request.headers.get("Authorization")

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
            )
            request.state.plane_id = payload.get("sub")
            request.state.plane_role = payload.get("role")
            request.state.jwt_payload = payload
        except JWTError as exc:
            logger.debug("JWT decode failed: %s", exc)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired token."},
            )
    else:
        # No token — leave identity unset.
        request.state.plane_id = None
        request.state.plane_role = None
        request.state.jwt_payload = None

    return await call_next(request)


# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(health_router)

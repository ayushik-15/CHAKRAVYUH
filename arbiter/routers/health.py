"""CHAKRAVYUH Arbiter — Health-check router.

Provides liveness and readiness probes for the Arbiter service and its
upstream dependencies (Merkle-log, PostgreSQL).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, status

from config import settings

logger = logging.getLogger("arbiter.health")

router = APIRouter(prefix="/health", tags=["health"])


@router.get(
    "",
    summary="Liveness probe",
    status_code=status.HTTP_200_OK,
)
async def health() -> dict:
    """Return basic health information for the Arbiter service."""
    return {
        "status": "healthy",
        "service": "arbiter",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/services",
    summary="Upstream service connectivity check",
    status_code=status.HTTP_200_OK,
)
async def health_services() -> dict:
    """Check connectivity to the Merkle-log service and PostgreSQL.

    Returns a per-service status map so orchestrators can identify which
    dependency is unhealthy.
    """
    services: dict[str, dict] = {}

    # ── Merkle-log ───────────────────────────────────────────────────────
    merkle_url = f"http://{settings.MERKLE_HOST}:{settings.MERKLE_PORT}/health"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(merkle_url)
            services["merkle-log"] = {
                "status": "healthy" if resp.status_code == 200 else "unhealthy",
                "status_code": resp.status_code,
            }
    except Exception as exc:
        logger.warning("Merkle-log health check failed: %s", exc)
        services["merkle-log"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    # ── PostgreSQL ───────────────────────────────────────────────────────
    try:
        # Attempt a lightweight connection check via asyncpg if available,
        # otherwise fall back to a DSN-reachability heuristic.
        import asyncpg  # type: ignore[import-untyped]

        conn = await asyncpg.connect(
            settings.POSTGRES_DSN.replace("+asyncpg", "")
        )
        await conn.execute("SELECT 1")
        await conn.close()
        services["postgres"] = {"status": "healthy"}
    except ImportError:
        services["postgres"] = {
            "status": "unknown",
            "error": "asyncpg not installed — cannot verify connection.",
        }
    except Exception as exc:
        logger.warning("PostgreSQL health check failed: %s", exc)
        services["postgres"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    overall = "healthy" if all(
        s.get("status") == "healthy" for s in services.values()
    ) else "degraded"

    return {
        "status": overall,
        "services": services,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


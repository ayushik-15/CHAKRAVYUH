"""CHAKRAVYUH Arbiter — Merkle transparency-log client.

Provides an async HTTP client that forwards every evaluation-pipeline event
to the Merkle-log microservice for cryptographic anchoring.  Each call
produces a new leaf in the transparency tree and returns a signed tree head.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import httpx

logger = logging.getLogger("arbiter.merkle_logger")


class MerkleLogger:
    """Async client for the Merkle-log ``/log/append`` endpoint.

    Usage::

        ml = MerkleLogger("http://merkle-log:8001")
        result = await ml.log_event("ROUND_START", round_id, {"key": "val"})
    """

    def __init__(self, merkle_url: str) -> None:
        """Store the base URL of the Merkle-log microservice.

        Args:
            merkle_url: Full base URL, e.g. ``"http://merkle-log:8001"``.
        """
        self._merkle_url = merkle_url.rstrip("/")

    async def log_event(
        self,
        event_type: str,
        round_id: UUID,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Append an event to the Merkle transparency log.

        Args:
            event_type: Event type string (e.g. ``"ROUND_START"``).
            round_id: UUID of the evaluation round.
            data: Optional JSON-serialisable payload.

        Returns:
            The response dict from the Merkle-log service (leaf_index,
            leaf_hash, tree_size, signed_tree_head), or ``None`` if the
            request failed.
        """
        url = f"{self._merkle_url}/log/append"
        payload = {
            "event_type": event_type,
            "round_id": str(round_id),
            "data": data or {},
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                result = resp.json()
                logger.debug(
                    "Merkle-logged %s for round %s (leaf=%s).",
                    event_type,
                    round_id,
                    result.get("leaf_index"),
                )
                return result
        except httpx.TimeoutException:
            logger.warning(
                "Merkle-log timeout while logging %s for round %s.",
                event_type,
                round_id,
            )
            return None
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Merkle-log HTTP %s while logging %s for round %s.",
                exc.response.status_code,
                event_type,
                round_id,
            )
            return None
        except Exception as exc:
            logger.warning(
                "Merkle-log unreachable while logging %s for round %s: %s",
                event_type,
                round_id,
                exc,
            )
            return None


"""CHAKRAVYUH Merkle-Log — PostgreSQL persistence layer.

Provides durable storage for log leaves and signed tree heads so the
transparency log survives restarts.  The in-memory :class:`MerkleTree` can be
rebuilt from the stored leaves at startup.

Tables
------
``leaves``
    One row per appended log entry (raw data + precomputed hash).

``tree_heads``
    One row per Signed Tree Head emitted after each append.  Auditors can
    query the latest head and verify consistency with their local state.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import asyncpg  # type: ignore[import-untyped]

logger = logging.getLogger("merkle-log.store")


class PostgresStore:
    """Async PostgreSQL store for Merkle-log leaves and tree heads.

    Usage::

        store = PostgresStore(dsn="postgresql://...")
        await store.init_db()
        leaf_id = await store.store_leaf(data, leaf_hash)
    """

    def __init__(self, dsn: str) -> None:
        """Create a store instance.

        Args:
            dsn: PostgreSQL connection string
                (e.g. ``postgresql://user:pass@host:5432/db``).
        """
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    async def init_db(self) -> None:
        """Create the connection pool and ensure tables exist.

        This method is idempotent — safe to call on every startup.
        """
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS leaves (
                    id         SERIAL PRIMARY KEY,
                    data       BYTEA        NOT NULL,
                    hash       BYTEA        NOT NULL,
                    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
                );
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tree_heads (
                    id         SERIAL PRIMARY KEY,
                    root_hash  BYTEA        NOT NULL,
                    tree_size  INTEGER      NOT NULL,
                    timestamp  DOUBLE PRECISION NOT NULL,
                    signature  BYTEA        NOT NULL,
                    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
                );
                """
            )
        logger.info("Database tables initialised.")

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None

    # ──────────────────────────────────────────────────────────────────────
    # Leaf operations
    # ──────────────────────────────────────────────────────────────────────

    async def store_leaf(self, data: bytes, leaf_hash: bytes) -> int:
        """Persist a leaf and return its auto-incremented id.

        Args:
            data: Raw entry bytes.
            leaf_hash: Precomputed SHA-256 hash of the leaf.

        Returns:
            The database-assigned leaf id (1-based).
        """
        assert self._pool is not None, "Call init_db() first."
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO leaves (data, hash) VALUES ($1, $2) RETURNING id",
                data,
                leaf_hash,
            )
            return row["id"]  # type: ignore[index]

    async def get_leaf(self, index: int) -> dict[str, Any]:
        """Fetch a single leaf by its zero-based tree index.

        The database id is 1-based, so we query ``id = index + 1``.

        Raises:
            ValueError: If the leaf does not exist.
        """
        assert self._pool is not None, "Call init_db() first."
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, data, hash, created_at FROM leaves WHERE id = $1",
                index + 1,
            )
        if row is None:
            raise ValueError(f"Leaf at index {index} not found.")
        return {
            "index": row["id"] - 1,
            "data": bytes(row["data"]),
            "hash": bytes(row["hash"]),
            "created_at": row["created_at"].isoformat(),
        }

    async def get_leaves(
        self, start: int, end: int
    ) -> list[dict[str, Any]]:
        """Fetch a range of leaves ``[start, end)`` by zero-based index.

        Args:
            start: Inclusive start index.
            end: Exclusive end index.

        Returns:
            List of leaf dicts ordered by index.
        """
        assert self._pool is not None, "Call init_db() first."
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, data, hash, created_at FROM leaves "
                "WHERE id >= $1 AND id < $2 ORDER BY id",
                start + 1,
                end + 1,
            )
        return [
            {
                "index": row["id"] - 1,
                "data": bytes(row["data"]),
                "hash": bytes(row["hash"]),
                "created_at": row["created_at"].isoformat(),
            }
            for row in rows
        ]

    # ──────────────────────────────────────────────────────────────────────
    # Tree head operations
    # ──────────────────────────────────────────────────────────────────────

    async def store_tree_head(self, sth: dict) -> None:
        """Persist a Signed Tree Head.

        Args:
            sth: Dict with ``root_hash``, ``tree_size``, ``timestamp``,
                ``signature`` (all bytes/numeric).
        """
        assert self._pool is not None, "Call init_db() first."
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tree_heads (root_hash, tree_size, timestamp, signature) "
                "VALUES ($1, $2, $3, $4)",
                sth["root_hash"],
                sth["tree_size"],
                sth["timestamp"],
                sth["signature"],
            )

    async def get_latest_tree_head(self) -> dict[str, Any] | None:
        """Return the most recent Signed Tree Head, or ``None`` if empty."""
        assert self._pool is not None, "Call init_db() first."
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT root_hash, tree_size, timestamp, signature, created_at "
                "FROM tree_heads ORDER BY id DESC LIMIT 1"
            )
        if row is None:
            return None
        return {
            "root_hash": bytes(row["root_hash"]),
            "tree_size": row["tree_size"],
            "timestamp": row["timestamp"],
            "signature": bytes(row["signature"]),
            "created_at": row["created_at"].isoformat(),
        }


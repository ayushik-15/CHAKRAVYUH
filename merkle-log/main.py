"""CHAKRAVYUH Merkle-Log — FastAPI application entry-point.

Boots the transparency-log microservice:

1. Initialises the :class:`MerkleTree`, :class:`LogSigner`, and
   :class:`PostgresStore`.
2. Rebuilds the in-memory tree from persisted leaves (crash recovery).
3. Registers the API router and health endpoint.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI

from api import init_services, router as log_router
from signer import LogSigner
from store import PostgresStore
from tree import MerkleTree

# ── Environment ──────────────────────────────────────────────────────────────
load_dotenv()

POSTGRES_DSN: str = os.getenv(
    "POSTGRES_DSN",
    "postgresql://chakravyuh:chakravyuh@postgres:5432/chakravyuh",
)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("merkle-log")


# ── Application lifespan ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown hooks.

    On startup:
        * Create the Merkle tree, Ed25519 signer, and Postgres store.
        * Initialise database tables (idempotent).
        * Rebuild the in-memory tree from persisted leaves.
        * Wire services into the API router.

    On shutdown:
        * Close the database connection pool.
    """
    tree = MerkleTree()
    signer = LogSigner()
    store = PostgresStore(dsn=POSTGRES_DSN)

    # ── Database init ────────────────────────────────────────────────────
    try:
        await store.init_db()
        logger.info("Database connection established.")

        # Rebuild tree from persisted leaves
        leaf_count = 0
        batch_size = 500
        while True:
            leaves = await store.get_leaves(leaf_count, leaf_count + batch_size)
            if not leaves:
                break
            for leaf in leaves:
                # Re-append raw data to rebuild the tree in correct order
                tree.append(leaf["data"])
                leaf_count += 1
        if leaf_count:
            logger.info(
                "Rebuilt in-memory tree from %d persisted leaves (root=%s).",
                leaf_count,
                tree.get_root().hex()[:16],
            )
    except Exception as exc:
        logger.warning(
            "Database unavailable — running in memory-only mode: %s", exc,
        )

    logger.info(
        "Ed25519 verification key: %s",
        signer.get_public_key().hex()[:16] + "…",
    )

    # Wire services
    init_services(tree, signer, store)
    logger.info("Merkle-log service started (tree_size=%d).", tree.get_tree_size())

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────
    await store.close()
    logger.info("Merkle-log service shut down.")


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="CHAKRAVYUH Merkle Transparency Log",
    description=(
        "Append-only transparency log backed by a binary Merkle tree and "
        "Ed25519-signed tree heads.  Provides inclusion and consistency "
        "proofs for auditability of the evaluation pipeline."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ── Health ───────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
async def health() -> dict:
    """Liveness probe for the Merkle-log service."""
    return {"status": "ok", "service": "merkle-log", "version": "0.1.0"}


# ── Router ───────────────────────────────────────────────────────────────────
app.include_router(log_router)

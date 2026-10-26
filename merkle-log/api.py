"""CHAKRAVYUH Merkle-Log — FastAPI router.

Exposes the transparency-log HTTP API consumed by the Arbiter, planes, and
external auditors.

Endpoints
---------
POST /log/append
    Append an event to the log and return the new leaf index + signed head.
GET  /log/proof/{leaf_index}
    Inclusion proof for a leaf.
GET  /log/consistency/{old_size}/{new_size}
    Consistency proof between two tree sizes.
GET  /log/head
    Latest Signed Tree Head.
GET  /log/entries
    Paginated leaf entries.
GET  /log/pubkey
    Ed25519 public verification key (base64).
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from signer import LogSigner
from store import PostgresStore
from tree import MerkleTree

logger = logging.getLogger("merkle-log.api")

router = APIRouter(prefix="/log", tags=["transparency-log"])

# ── Shared state (injected at startup via init_services) ─────────────────────
_tree: MerkleTree | None = None
_signer: LogSigner | None = None
_store: PostgresStore | None = None


def init_services(
    tree: MerkleTree, signer: LogSigner, store: PostgresStore
) -> None:
    """Wire the singleton services after FastAPI startup.

    Called from :func:`main.lifespan`.
    """
    global _tree, _signer, _store  # noqa: PLW0603
    _tree = tree
    _signer = signer
    _store = store


def _require_services() -> tuple[MerkleTree, LogSigner, PostgresStore]:
    """Return the service triple, or raise 503 if not yet initialised."""
    if _tree is None or _signer is None or _store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Services not yet initialised — try again shortly.",
        )
    return _tree, _signer, _store


# ── Request / response models ───────────────────────────────────────────────


class AppendRequest(BaseModel):
    """Body for the append endpoint."""

    event_type: str = Field(..., description="Event type (e.g. ROUND_START).")
    round_id: str = Field(..., description="UUID of the evaluation round.")
    data: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary event payload."
    )


class AppendResponse(BaseModel):
    """Response after a successful append."""

    leaf_index: int
    leaf_hash: str  # hex
    tree_size: int
    signed_tree_head: dict[str, Any]


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/append",
    summary="Append an event to the transparency log",
    status_code=status.HTTP_201_CREATED,
    response_model=AppendResponse,
)
async def append_entry(body: AppendRequest) -> AppendResponse:
    """Hash the event, append it to the Merkle tree, sign a new tree head,
    and persist both leaf and STH to PostgreSQL.
    """
    tree, signer, store = _require_services()

    # Canonical JSON encoding of the entry
    entry_bytes = json.dumps(
        {
            "event_type": body.event_type,
            "round_id": body.round_id,
            "data": body.data,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    # Append to in-memory tree
    leaf_index = tree.append(entry_bytes)
    leaf_hash = tree.get_leaf_hash(leaf_index)

    # Sign tree head
    root = tree.get_root()
    tree_size = tree.get_tree_size()
    sth = signer.sign_tree_head(root, tree_size)

    # Persist
    await store.store_leaf(entry_bytes, leaf_hash)
    await store.store_tree_head(sth)

    logger.info(
        "Appended leaf %d (tree_size=%d, root=%s).",
        leaf_index,
        tree_size,
        root.hex()[:16],
    )

    return AppendResponse(
        leaf_index=leaf_index,
        leaf_hash=leaf_hash.hex(),
        tree_size=tree_size,
        signed_tree_head=_serialise_sth(sth),
    )


@router.get(
    "/proof/{leaf_index}",
    summary="Get inclusion proof for a leaf",
)
async def inclusion_proof(leaf_index: int) -> dict:
    """Return an inclusion proof for the leaf at *leaf_index*.

    The proof consists of ``(sibling_hash, direction)`` pairs from the leaf
    to the root.  Any holder of the signed root hash can verify the leaf's
    membership without downloading the full log.
    """
    tree, signer, _store = _require_services()

    if leaf_index < 0 or leaf_index >= tree.get_tree_size():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Leaf index {leaf_index} out of range.",
        )

    proof = tree.get_inclusion_proof(leaf_index)
    root = tree.get_root()

    return {
        "leaf_index": leaf_index,
        "leaf_hash": tree.get_leaf_hash(leaf_index).hex(),
        "tree_size": tree.get_tree_size(),
        "root_hash": root.hex(),
        "proof": [
            {"hash": h.hex(), "direction": d} for h, d in proof
        ],
    }


@router.get(
    "/consistency/{old_size}/{new_size}",
    summary="Get consistency proof between tree sizes",
)
async def consistency_proof(old_size: int, new_size: int) -> dict:
    """Return a consistency proof showing the tree at *old_size* is a prefix
    of the tree at *new_size*.

    This is the core mechanism auditors use to verify the log is append-only.
    """
    tree, _signer, _store = _require_services()

    try:
        proof = tree.get_consistency_proof(old_size, new_size)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return {
        "old_size": old_size,
        "new_size": new_size,
        "proof": [h.hex() for h in proof],
    }


@router.get(
    "/head",
    summary="Get latest Signed Tree Head",
)
async def tree_head() -> dict:
    """Return the most recently signed tree head.

    The STH contains the root hash, tree size, timestamp, and an Ed25519
    signature.  Auditors should cache the last-seen STH and request a
    consistency proof to the new one on each poll.
    """
    tree, signer, store = _require_services()

    # Try DB first, fall back to computing from in-memory tree
    sth = await store.get_latest_tree_head()
    if sth is None:
        # Tree may be empty or DB not yet populated
        root = tree.get_root()
        size = tree.get_tree_size()
        sth = signer.sign_tree_head(root, size)

    return _serialise_sth(sth)


@router.get(
    "/entries",
    summary="Get log entries in range",
)
async def get_entries(
    start: int = Query(0, ge=0, description="Start index (inclusive)."),
    end: int = Query(10, ge=0, description="End index (exclusive)."),
) -> dict:
    """Return log entries in the range ``[start, end)``."""
    _tree, _signer, store = _require_services()

    if end <= start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'end' must be greater than 'start'.",
        )

    try:
        leaves = await store.get_leaves(start, end)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch entries: {exc}",
        )

    # Convert raw bytes for JSON serialisation
    return {
        "start": start,
        "end": end,
        "entries": [
            {
                "index": leaf["index"],
                "data": leaf["data"].decode("utf-8", errors="replace"),
                "hash": leaf["hash"].hex(),
                "created_at": leaf["created_at"],
            }
            for leaf in leaves
        ],
    }


@router.get(
    "/pubkey",
    summary="Get Ed25519 public verification key",
)
async def public_key() -> dict:
    """Return the log's Ed25519 public verification key (base64-encoded).

    Any party can use this key to independently verify Signed Tree Heads.
    """
    _tree, signer, _store = _require_services()

    raw = signer.get_public_key()
    return {
        "public_key": base64.b64encode(raw).decode("ascii"),
        "algorithm": "Ed25519",
    }


# ── Helpers ──────────────────────────────────────────────────────────────────


def _serialise_sth(sth: dict) -> dict[str, Any]:
    """Convert an STH dict to a JSON-friendly representation."""
    return {
        "root_hash": sth["root_hash"].hex() if isinstance(sth["root_hash"], bytes) else sth["root_hash"],
        "tree_size": sth["tree_size"],
        "timestamp": sth["timestamp"],
        "signature": base64.b64encode(sth["signature"]).decode("ascii") if isinstance(sth["signature"], bytes) else sth["signature"],
    }


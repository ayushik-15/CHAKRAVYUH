"""CHAKRAVYUH Arbiter — CREP round-lifecycle router.

Exposes the HTTP API that Red, Blue, and Observer planes use to drive the
Commit-Reveal Evaluation Protocol.  Every endpoint enforces caller identity
(via JWT ``plane_role``) and CREP state-machine transitions (via the
:class:`CREPEngine`).
"""

from __future__ import annotations

import base64
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from models.round import (
    CommitRequest,
    PayloadRequest,
    RevealRequest,
    Round,
    RoundResponse,
    VerdictRequest,
)
from services.crep import CREPEngine
from services.isolation import PlaneRouter

logger = logging.getLogger("arbiter.rounds")

router = APIRouter(tags=["rounds"])

# ── Singletons (created once, shared across requests) ────────────────────────
_crep_engine = CREPEngine()
_plane_router = PlaneRouter()


# ── Dependency helpers ───────────────────────────────────────────────────────


def _plane_role(request: Request) -> str | None:
    """Extract the caller's plane role from the JWT-injected request state."""
    return getattr(request.state, "plane_role", None)


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/round/new",
    summary="Create a new evaluation round",
    status_code=status.HTTP_201_CREATED,
    response_model=RoundResponse,
)
async def create_round(request: Request) -> RoundResponse:
    """Create a fresh evaluation round and return its ID.

    Only the **Red** plane may create rounds.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, "/round/new")

    rnd = _crep_engine.create_round()
    return RoundResponse(round=rnd)


@router.post(
    "/round/{round_id}/commit",
    summary="Submit commitment hash",
    response_model=RoundResponse,
)
async def commit(round_id: UUID, body: CommitRequest, request: Request) -> RoundResponse:
    """Red plane submits a SHA-256 commitment hash for the round."""
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/commit")

    rnd = _crep_engine.receive_commitment(round_id, body.commitment_hash)
    return RoundResponse(round=rnd)


@router.post(
    "/round/{round_id}/payload",
    summary="Submit sealed (encrypted) payload",
    response_model=RoundResponse,
)
async def payload(round_id: UUID, body: PayloadRequest, request: Request) -> RoundResponse:
    """Red plane sends a NaCl SealedBox-encrypted payload.

    The Arbiter decrypts it internally but **never** exposes the plaintext
    to the Blue plane.  After decryption the round automatically forwards
    the payload to the LLM plane.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/payload")

    rnd = _crep_engine.receive_sealed_payload(round_id, body.sealed_payload)

    # Automatically forward the decrypted payload to the LLM plane
    await _crep_engine.forward_to_llm(round_id)

    # Re-fetch the round after forwarding (status is now EVALUATING)
    rnd = _crep_engine.get_round(round_id)
    return RoundResponse(round=rnd)


@router.get(
    "/round/{round_id}/scores",
    summary="Get derived scores (Blue only)",
)
async def scores(round_id: UUID, request: Request) -> dict:
    """Return derived metrics for the round — **never** the raw payload.

    Only the **Blue** plane may call this endpoint.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/scores")

    return _crep_engine.get_derived_scores(round_id)


@router.post(
    "/round/{round_id}/verdict",
    summary="Submit safety verdict",
    response_model=RoundResponse,
)
async def verdict(round_id: UUID, body: VerdictRequest, request: Request) -> RoundResponse:
    """Blue plane submits a safety verdict on the LLM response."""
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/verdict")

    rnd = _crep_engine.receive_verdict(
        round_id,
        body.verdict,
        body.confidence,
        body.reasoning,
    )
    return RoundResponse(round=rnd)


@router.post(
    "/round/{round_id}/reveal",
    summary="Reveal payload + nonce for verification",
    response_model=dict,
)
async def reveal(round_id: UUID, body: RevealRequest, request: Request) -> dict:
    """Red plane reveals the original payload and nonce.

    The Arbiter recomputes ``SHA-256(payload || nonce)`` and compares it
    against the stored commitment hash.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/reveal")

    match, rnd = _crep_engine.verify_reveal(round_id, body.payload, body.nonce)

    return {
        "verified": match,
        "round": rnd.model_dump(mode="json"),
        "status": rnd.status.value,
    }


@router.get(
    "/round/{round_id}/status",
    summary="Get round status",
)
async def round_status(round_id: UUID, request: Request) -> dict:
    """Return the current status of a round.

    Accessible to **all** authenticated planes.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/status")

    rnd = _crep_engine.get_round(round_id)
    return {
        "round_id": str(rnd.id),
        "status": rnd.status.value,
        "created_at": rnd.created_at.isoformat(),
        "updated_at": rnd.updated_at.isoformat(),
    }


@router.get(
    "/round/{round_id}/verify",
    summary="Verify commitment (observer)",
)
async def verify(round_id: UUID, request: Request) -> dict:
    """Check whether the round's commitment has been verified.

    Accessible to **observers**.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, f"/round/{round_id}/verify")

    rnd = _crep_engine.get_round(round_id)
    return {
        "round_id": str(rnd.id),
        "status": rnd.status.value,
        "verified": rnd.status == "VERIFIED",
        "commitment_hash": rnd.commitment_hash,
    }


@router.get(
    "/arbiter/pubkey",
    summary="Get Arbiter public key",
)
async def pubkey(request: Request) -> dict:
    """Return the Arbiter's X25519 public key (base64-encoded).

    Red planes use this key to seal payloads via NaCl ``SealedBox``.
    """
    role = _plane_role(request)
    _plane_router.enforce(role, "/arbiter/pubkey")

    raw_key = _crep_engine.get_public_key()
    return {
        "public_key": base64.b64encode(raw_key).decode("ascii"),
        "algorithm": "X25519-SealedBox",
    }


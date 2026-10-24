"""CHAKRAVYUH Arbiter — Round models.

Defines the data structures that track the lifecycle of a single evaluation
round, as well as the request / response schemas consumed by the API routers.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, confloat


# ── Round lifecycle ──────────────────────────────────────────────────────────


class RoundStatus(str, enum.Enum):
    """Possible states of an evaluation round."""

    CREATED = "CREATED"
    COMMITTED = "COMMITTED"
    PAYLOAD_SENT = "PAYLOAD_SENT"
    EVALUATING = "EVALUATING"
    VERDICT_RECEIVED = "VERDICT_RECEIVED"
    REVEALED = "REVEALED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


class Round(BaseModel):
    """Core representation of an evaluation round.

    Attributes:
        id: Unique identifier for the round.
        status: Current lifecycle state.
        commitment_hash: SHA-256 commitment from the red plane.
        sealed_payload: Base64-encoded sealed payload for the LLM.
        llm_response: Raw LLM output returned during evaluation.
        verdict: Safety verdict (``safe`` / ``unsafe``).
        created_at: When the round was created (UTC).
        updated_at: Last update timestamp (UTC).
    """

    id: UUID = Field(default_factory=uuid4, description="Unique round identifier.")
    status: RoundStatus = Field(
        default=RoundStatus.CREATED, description="Current round status."
    )
    commitment_hash: Optional[str] = Field(
        None, description="SHA-256 commitment hash from the red plane."
    )
    sealed_payload: Optional[str] = Field(
        None, description="Base64-encoded sealed payload."
    )
    llm_response: Optional[str] = Field(
        None, description="Raw response from the LLM plane."
    )
    verdict: Optional[str] = Field(
        None, description="Safety verdict: 'safe' or 'unsafe'."
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Round creation timestamp (UTC).",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last update timestamp (UTC).",
    )


# ── Request schemas ──────────────────────────────────────────────────────────


class CommitRequest(BaseModel):
    """Payload sent by the red plane to commit a hash before revealing."""

    commitment_hash: str = Field(
        ..., description="SHA-256 hash committing to a future payload."
    )


class PayloadRequest(BaseModel):
    """Sealed payload forwarded to the LLM plane for evaluation."""

    sealed_payload: str = Field(
        ..., description="Base64-encoded sealed payload."
    )


class RevealRequest(BaseModel):
    """Reveal of the original payload and nonce to verify the commitment."""

    payload: str = Field(..., description="Original plaintext payload.")
    nonce: str = Field(..., description="Hex-encoded nonce used in the commitment.")


class VerdictRequest(BaseModel):
    """Blue plane verdict on the LLM response safety.

    Attributes:
        verdict: ``safe`` or ``unsafe``.
        confidence: Confidence score between 0 and 1.
        reasoning: Human-readable explanation for the verdict.
    """

    verdict: str = Field(
        ..., pattern=r"^(safe|unsafe)$", description="Safety verdict."
    )
    confidence: confloat(ge=0.0, le=1.0) = Field(  # type: ignore[valid-type]
        ..., description="Confidence score in [0, 1]."
    )
    reasoning: str = Field(..., description="Explanation for the verdict.")


# ── Response schemas ─────────────────────────────────────────────────────────


class RoundResponse(BaseModel):
    """Round data returned to callers, optionally including a Merkle proof.

    Attributes:
        round: The full round object.
        merkle_proof: Optional Merkle-tree inclusion proof.
    """

    round: Round = Field(..., description="Full round data.")
    merkle_proof: Optional[dict[str, Any]] = Field(
        None, description="Merkle-tree inclusion proof, when available."
    )


"""CHAKRAVYUH Arbiter — Event models.

Defines the canonical event types that flow through the evaluation pipeline
and the ``EvalEvent`` envelope that wraps every such event.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventType(str, enum.Enum):
    """Enumeration of lifecycle events within an evaluation round."""

    ROUND_START = "ROUND_START"
    COMMITMENT_RECEIVED = "COMMITMENT_RECEIVED"
    PAYLOAD_SEALED = "PAYLOAD_SEALED"
    LLM_RESPONSE = "LLM_RESPONSE"
    VERDICT_SUBMITTED = "VERDICT_SUBMITTED"
    REVEAL_VERIFIED = "REVEAL_VERIFIED"
    ROUND_COMPLETE = "ROUND_COMPLETE"


class EvalEvent(BaseModel):
    """Immutable record of a single pipeline event.

    Attributes:
        id: Unique identifier for this event.
        event_type: The kind of event (see :class:`EventType`).
        timestamp: UTC time the event was recorded.
        round_id: The evaluation round this event belongs to.
        data: Arbitrary JSON-serialisable payload carrying event-specific info.
        signature: Optional cryptographic signature for tamper evidence.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique event identifier.")
    event_type: EventType = Field(..., description="Type of evaluation event.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the event occurred.",
    )
    round_id: UUID = Field(..., description="ID of the evaluation round.")
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload.")
    signature: Optional[str] = Field(
        None,
        description="Optional cryptographic signature for integrity verification.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "event_type": "ROUND_START",
                    "round_id": "550e8400-e29b-41d4-a716-446655440000",
                    "data": {"initiated_by": "red-plane"},
                }
            ]
        }
    }


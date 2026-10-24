"""CHAKRAVYUH Arbiter — CREP (Commit-Reveal Evaluation Protocol) Engine.

Implements the full lifecycle of an evaluation round:

    1. **Create** — a new round is opened.
    2. **Commit** — the Red plane commits a SHA-256 hash.
    3. **Seal**   — Red sends an X25519-sealed payload; the Arbiter decrypts it.
    4. **Forward** — the decrypted payload is sent to the LLM plane.
    5. **Verdict** — the Blue plane renders a safety verdict on the response.
    6. **Reveal**  — Red reveals the original payload + nonce for verification.

The engine enforces strict state-machine transitions — every method validates
that the round is in the expected status before proceeding.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import httpx
from fastapi import HTTPException, status
from nacl.public import PrivateKey, SealedBox

from config import settings
from models.events import EvalEvent, EventType
from models.round import Round, RoundStatus

logger = logging.getLogger("arbiter.crep")


class CREPEngine:
    """Core CREP state-machine and cryptographic service.

    Attributes:
        _private_key: X25519 private key used to decrypt sealed payloads.
        _public_key: Corresponding public key — shared with the Red plane.
        _rounds: In-memory store of active rounds keyed by UUID.
        _decrypted_payloads: Decrypted plaintext payloads, **never** exposed
            to the Blue plane or any external consumer.
        _events: Append-only log of :class:`EvalEvent` instances per round.
        _round_timings: Timing metadata used to derive latency scores.
    """

    def __init__(self) -> None:
        # ── X25519 keypair for SealedBox ─────────────────────────────────
        self._private_key = PrivateKey.generate()
        self._public_key = self._private_key.public_key

        # ── In-memory stores ─────────────────────────────────────────────
        self._rounds: dict[UUID, Round] = {}
        self._decrypted_payloads: dict[UUID, str] = {}
        self._events: dict[UUID, list[EvalEvent]] = {}
        self._round_timings: dict[UUID, dict[str, float]] = {}

        logger.info("CREPEngine initialised — X25519 keypair generated.")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _get_round(self, round_id: UUID) -> Round:
        """Fetch a round or raise 404."""
        rnd = self._rounds.get(round_id)
        if rnd is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Round {round_id} not found.",
            )
        return rnd

    def _assert_status(self, rnd: Round, expected: RoundStatus) -> None:
        """Ensure the round is in *expected* status, or raise 409 Conflict."""
        if rnd.status != expected:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Round {rnd.id} is in status {rnd.status.value}; "
                    f"expected {expected.value}."
                ),
            )

    def _touch(self, rnd: Round) -> None:
        """Update the ``updated_at`` timestamp on a round."""
        rnd.updated_at = datetime.now(timezone.utc)

    def _log_event(
        self,
        round_id: UUID,
        event_type: EventType,
        data: dict[str, Any] | None = None,
    ) -> EvalEvent:
        """Append an event to the round's event log and return it."""
        event = EvalEvent(
            event_type=event_type,
            round_id=round_id,
            data=data or {},
        )
        self._events.setdefault(round_id, []).append(event)
        logger.info("Event %s logged for round %s", event_type.value, round_id)
        return event

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def create_round(self) -> Round:
        """Create a new evaluation round.

        Returns:
            The newly created :class:`Round` in ``CREATED`` status.
        """
        round_id = uuid4()
        rnd = Round(id=round_id, status=RoundStatus.CREATED)
        self._rounds[round_id] = rnd
        self._round_timings[round_id] = {"created_at": time.monotonic()}
        self._log_event(round_id, EventType.ROUND_START)
        logger.info("Round %s created.", round_id)
        return rnd

    def receive_commitment(self, round_id: UUID, commitment_hash: str) -> Round:
        """Record a commitment hash from the Red plane.

        Args:
            round_id: Target round.
            commitment_hash: SHA-256 hex digest committing to a future payload.

        Returns:
            The updated round in ``COMMITTED`` status.

        Raises:
            HTTPException: 404 if round not found, 409 if wrong status.
        """
        rnd = self._get_round(round_id)
        self._assert_status(rnd, RoundStatus.CREATED)

        rnd.commitment_hash = commitment_hash
        rnd.status = RoundStatus.COMMITTED
        self._touch(rnd)

        self._log_event(
            round_id,
            EventType.COMMITMENT_RECEIVED,
            {"commitment_hash": commitment_hash},
        )
        logger.info("Commitment received for round %s.", round_id)
        return rnd

    def receive_sealed_payload(self, round_id: UUID, sealed_payload_b64: str) -> Round:
        """Decrypt a sealed payload from the Red plane.

        The payload is encrypted with the Arbiter's X25519 public key using
        NaCl's *SealedBox* — only the Arbiter can decrypt it.  The decrypted
        plaintext is stored internally and is **never** exposed to the Blue
        plane.

        Args:
            round_id: Target round.
            sealed_payload_b64: Base64-encoded NaCl SealedBox ciphertext.

        Returns:
            The updated round in ``PAYLOAD_SENT`` status.  The returned
            ``sealed_payload`` field contains the *original ciphertext*, not
            the plaintext.

        Raises:
            HTTPException: 404 / 409 / 400 on invalid input.
        """
        rnd = self._get_round(round_id)
        self._assert_status(rnd, RoundStatus.COMMITTED)

        # Decrypt using our private key
        try:
            sealed_bytes = base64.b64decode(sealed_payload_b64)
            unseal_box = SealedBox(self._private_key)
            plaintext = unseal_box.decrypt(sealed_bytes).decode("utf-8")
        except Exception as exc:
            logger.error("Payload decryption failed for round %s: %s", round_id, exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to decrypt sealed payload: {exc}",
            )

        # Store plaintext internally (NEVER expose to Blue)
        self._decrypted_payloads[round_id] = plaintext
        rnd.sealed_payload = sealed_payload_b64  # keep ciphertext on record
        rnd.status = RoundStatus.PAYLOAD_SENT
        self._touch(rnd)
        self._round_timings[round_id]["payload_received_at"] = time.monotonic()

        self._log_event(
            round_id,
            EventType.PAYLOAD_SEALED,
            {"payload_length": len(plaintext)},
        )
        logger.info("Sealed payload received & decrypted for round %s.", round_id)
        return rnd

    async def forward_to_llm(self, round_id: UUID) -> str:
        """Forward the decrypted payload to the LLM plane and record the
        response.

        Args:
            round_id: Target round (must be in ``PAYLOAD_SENT`` status).

        Returns:
            The raw LLM response text.

        Raises:
            HTTPException: 404 / 409 / 502 on upstream failure.
        """
        rnd = self._get_round(round_id)
        self._assert_status(rnd, RoundStatus.PAYLOAD_SENT)

        plaintext = self._decrypted_payloads.get(round_id)
        if plaintext is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Decrypted payload missing — internal error.",
            )

        # POST to the LLM plane
        llm_url = f"{settings.LLM_PLANE_URL}/evaluate"
        self._round_timings[round_id]["llm_sent_at"] = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    llm_url,
                    json={"prompt": plaintext, "round_id": str(round_id)},
                )
                resp.raise_for_status()
                llm_response = resp.json().get("response", resp.text)
        except httpx.HTTPStatusError as exc:
            logger.error("LLM plane returned %s for round %s", exc.response.status_code, round_id)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"LLM plane error: {exc.response.status_code}",
            )
        except Exception as exc:
            logger.error("LLM plane unreachable for round %s: %s", round_id, exc)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"LLM plane unreachable: {exc}",
            )

        self._round_timings[round_id]["llm_received_at"] = time.monotonic()
        rnd.llm_response = llm_response
        rnd.status = RoundStatus.EVALUATING
        self._touch(rnd)

        self._log_event(
            round_id,
            EventType.LLM_RESPONSE,
            {"response_length": len(llm_response)},
        )
        logger.info("LLM response received for round %s (%d chars).", round_id, len(llm_response))
        return llm_response

    def receive_verdict(
        self,
        round_id: UUID,
        verdict: str,
        confidence: float,
        reasoning: str,
    ) -> Round:
        """Record a safety verdict from the Blue plane.

        Args:
            round_id: Target round.
            verdict: ``"safe"`` or ``"unsafe"``.
            confidence: Confidence score ∈ [0, 1].
            reasoning: Human-readable justification.

        Returns:
            The updated round in ``VERDICT_RECEIVED`` status.
        """
        rnd = self._get_round(round_id)
        self._assert_status(rnd, RoundStatus.EVALUATING)

        rnd.verdict = verdict
        rnd.status = RoundStatus.VERDICT_RECEIVED
        self._touch(rnd)

        self._log_event(
            round_id,
            EventType.VERDICT_SUBMITTED,
            {
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
            },
        )
        logger.info(
            "Verdict for round %s: %s (confidence=%.2f).",
            round_id, verdict, confidence,
        )
        return rnd

    def verify_reveal(
        self,
        round_id: UUID,
        payload: str,
        nonce_hex: str,
    ) -> tuple[bool, Round]:
        """Verify that the revealed payload + nonce match the commitment.

        Computes ``SHA-256(payload.encode() + bytes.fromhex(nonce_hex))`` and
        compares against the stored ``commitment_hash``.

        Args:
            round_id: Target round.
            payload: The original plaintext payload.
            nonce_hex: Hex-encoded nonce used in the original commitment.

        Returns:
            A tuple of ``(match, round)`` where *match* is ``True`` if the
            commitment is verified, ``False`` otherwise.
        """
        rnd = self._get_round(round_id)
        if rnd.status not in (RoundStatus.VERDICT_RECEIVED, RoundStatus.REVEALED):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Round {rnd.id} is in status {rnd.status.value}; "
                    f"expected VERDICT_RECEIVED or REVEALED."
                ),
            )

        try:
            nonce_bytes = bytes.fromhex(nonce_hex)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid hex nonce.",
            )

        computed_hash = hashlib.sha256(
            payload.encode("utf-8") + nonce_bytes
        ).hexdigest()

        match = computed_hash == rnd.commitment_hash

        if match:
            rnd.status = RoundStatus.VERIFIED
            self._log_event(
                round_id,
                EventType.REVEAL_VERIFIED,
                {"computed_hash": computed_hash, "match": True},
            )
            logger.info("Reveal VERIFIED for round %s.", round_id)
        else:
            rnd.status = RoundStatus.FAILED
            self._log_event(
                round_id,
                EventType.REVEAL_VERIFIED,
                {
                    "computed_hash": computed_hash,
                    "expected_hash": rnd.commitment_hash,
                    "match": False,
                },
            )
            logger.warning(
                "Reveal FAILED for round %s — hash mismatch "
                "(computed=%s, expected=%s).",
                round_id, computed_hash, rnd.commitment_hash,
            )

        self._touch(rnd)
        return match, rnd

    # ──────────────────────────────────────────────────────────────────────
    # Read-only accessors
    # ──────────────────────────────────────────────────────────────────────

    def get_public_key(self) -> bytes:
        """Return the Arbiter's X25519 public key (raw 32 bytes).

        Red planes use this key to seal payloads via NaCl ``SealedBox``.
        """
        return bytes(self._public_key)

    def get_round(self, round_id: UUID) -> Round:
        """Return the current state of a round.

        Raises:
            HTTPException: 404 if the round does not exist.
        """
        return self._get_round(round_id)

    def get_derived_scores(self, round_id: UUID) -> dict[str, Any]:
        """Return **only** derived metrics for a round — never raw payload.

        This is the sole view the Blue plane gets.  It includes:

        * ``response_length`` — character count of the LLM response.
        * ``token_count_estimate`` — rough whitespace-split token count.
        * ``llm_latency_seconds`` — wall-clock time for the LLM call (if
          available).

        Raises:
            HTTPException: 404 if round not found, 409 if no LLM response yet.
        """
        rnd = self._get_round(round_id)

        if rnd.llm_response is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LLM response not yet available for this round.",
            )

        scores: dict[str, Any] = {
            "round_id": str(round_id),
            "response_length": len(rnd.llm_response),
            "token_count_estimate": len(rnd.llm_response.split()),
        }

        timings = self._round_timings.get(round_id, {})
        sent = timings.get("llm_sent_at")
        received = timings.get("llm_received_at")
        if sent is not None and received is not None:
            scores["llm_latency_seconds"] = round(received - sent, 4)

        return scores


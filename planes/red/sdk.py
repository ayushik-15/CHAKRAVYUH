"""
CHAKRAVYUH — Red Team Client SDK

Provides the ``RedTeamClient`` class that implements the Red-side of the
Commit-Reveal Evaluation Protocol (CREP).  All communication with the
Arbiter goes through typed helper methods so the attack runner
(``attacker.py``) stays high-level and readable.

Cryptographic primitives
-------------------------
* **Commitment:** SHA-256(payload ‖ nonce)
* **Sealed payload:** X25519 + XSalsa20-Poly1305 via PyNaCl ``SealedBox``
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Dict

import requests
from nacl.public import PublicKey, SealedBox

logger = logging.getLogger(__name__)


class RedTeamClient:
    """HTTP client that drives the Red-side CREP flow against the Arbiter.

    Parameters
    ----------
    arbiter_url : str
        Base URL of the Arbiter service (e.g. ``http://arbiter:8000``).
        Must **not** end with a trailing slash.
    timeout : float
        Default request timeout in seconds.
    """

    def __init__(self, arbiter_url: str, timeout: float = 30.0) -> None:
        self.arbiter_url: str = arbiter_url.rstrip("/")
        self.timeout: float = timeout
        self._session: requests.Session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        logger.info("RedTeamClient initialised → Arbiter at %s", self.arbiter_url)

    # ------------------------------------------------------------------
    # CREP Step 1 — Commit
    # ------------------------------------------------------------------

    def commit(self, payload: str, nonce: bytes) -> Dict[str, Any]:
        """Submit a SHA-256 commitment of *payload* ‖ *nonce* to the Arbiter.

        The Arbiter stores the commitment hash but does **not** learn the
        payload or nonce at this stage — it only receives the digest.

        Parameters
        ----------
        payload : str
            The adversarial prompt in plain text.
        nonce : bytes
            A cryptographically random nonce (≥ 16 bytes recommended).

        Returns
        -------
        dict
            JSON response from ``POST /round/commit``.
        """
        commitment_hash: str = hashlib.sha256(
            payload.encode("utf-8") + nonce
        ).hexdigest()

        logger.info("Committing — hash: %s…", commitment_hash[:16])

        response = self._session.post(
            f"{self.arbiter_url}/round/commit",
            json={"commitment_hash": commitment_hash},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # CREP Step 2 — Send sealed (encrypted) payload
    # ------------------------------------------------------------------

    def send_sealed_payload(
        self, payload: str, arbiter_public_key: bytes
    ) -> Dict[str, Any]:
        """Encrypt *payload* with the Arbiter's public key and send it.

        Encryption uses **X25519 key-agreement + XSalsa20-Poly1305 AEAD**
        via PyNaCl's ``SealedBox``.  The Arbiter is the only party that
        can decrypt — the Blue plane never sees the raw payload.

        Parameters
        ----------
        payload : str
            The adversarial prompt in plain text.
        arbiter_public_key : bytes
            The Arbiter's 32-byte Curve25519 public key.

        Returns
        -------
        dict
            JSON response from ``POST /round/payload``.
        """
        public_key = PublicKey(arbiter_public_key)
        sealed_box = SealedBox(public_key)
        encrypted: bytes = sealed_box.encrypt(payload.encode("utf-8"))
        sealed_b64: str = base64.b64encode(encrypted).decode("ascii")

        logger.info(
            "Sending sealed payload — %d bytes encrypted → %d chars base64",
            len(encrypted),
            len(sealed_b64),
        )

        response = self._session.post(
            f"{self.arbiter_url}/round/payload",
            json={"sealed_payload": sealed_b64},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # CREP Step 3 — Reveal
    # ------------------------------------------------------------------

    def reveal(self, payload: str, nonce: bytes) -> Dict[str, Any]:
        """Reveal the original payload and nonce for commitment verification.

        The Arbiter re-computes ``SHA-256(payload ‖ nonce)`` and checks it
        against the commitment stored in Step 1.  A match proves the Red
        team did not swap the payload after seeing the evaluation result.

        Parameters
        ----------
        payload : str
            The original plain-text payload (must match the committed one).
        nonce : bytes
            The original nonce used during commitment.

        Returns
        -------
        dict
            JSON response from ``POST /round/reveal`` with the
            verification result (``{"verified": true/false, ...}``).
        """
        nonce_hex: str = nonce.hex()
        logger.info("Revealing payload — nonce (hex): %s…", nonce_hex[:16])

        response = self._session.post(
            f"{self.arbiter_url}/round/reveal",
            json={"payload": payload, "nonce": nonce_hex},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Round status
    # ------------------------------------------------------------------

    def get_round_status(self, round_id: str) -> Dict[str, Any]:
        """Query the current status of an evaluation round.

        Parameters
        ----------
        round_id : str
            UUID of the round as returned by the Arbiter on commitment.

        Returns
        -------
        dict
            JSON response from ``GET /round/{round_id}/status``.
        """
        logger.debug("Fetching status for round %s", round_id)

        response = self._session.get(
            f"{self.arbiter_url}/round/{round_id}/status",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

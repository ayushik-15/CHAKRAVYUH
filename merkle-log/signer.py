"""CHAKRAVYUH Merkle-Log — Ed25519 tree-head signer.

Every time the Merkle tree grows, a new **Signed Tree Head (STH)** is produced.
The STH binds the root hash, tree size, and wall-clock timestamp under an
Ed25519 signature, providing:

* **Non-repudiation** — the log operator cannot deny having published a
  particular tree head.
* **Freshness** — the timestamp lets monitors detect stale or replayed heads.
* **Consistency anchoring** — auditors compare successive STHs to verify the
  log is append-only (via consistency proofs against the signed roots).

The signing key is ephemeral by default (generated at startup) but can be
seeded from an environment variable for deterministic deployments.  The
**public verification key** is exposed via the API so any party can verify
STHs independently.
"""

from __future__ import annotations

import struct
import time

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey


class LogSigner:
    """Ed25519 signer for Merkle tree heads.

    Attributes:
        _signing_key: 32-byte Ed25519 private key.
        _verify_key: Corresponding public key.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        """Initialise a new signer.

        Args:
            seed: Optional 32-byte seed for deterministic key generation.
                If ``None``, a random key is generated.
        """
        if seed is not None:
            self._signing_key = SigningKey(seed)
        else:
            self._signing_key = SigningKey.generate()
        self._verify_key: VerifyKey = self._signing_key.verify_key

    # ──────────────────────────────────────────────────────────────────────
    # Signing
    # ──────────────────────────────────────────────────────────────────────

    def sign_tree_head(
        self,
        root_hash: bytes,
        tree_size: int,
        timestamp: float | None = None,
    ) -> dict:
        """Create a Signed Tree Head (STH).

        The message that is signed is the concatenation of:
            ``root_hash (32 B) || tree_size (8 B big-endian) || timestamp (8 B double)``

        This deterministic encoding ensures the signature covers every field
        and cannot be reinterpreted.

        Args:
            root_hash: 32-byte Merkle root.
            tree_size: Number of leaves in the tree.
            timestamp: UNIX epoch seconds.  Defaults to ``time.time()``.

        Returns:
            A dict with keys ``root_hash``, ``tree_size``, ``timestamp``,
            ``signature``, each stored as ``bytes`` or numeric types.
        """
        if timestamp is None:
            timestamp = time.time()

        message = self._encode_sth_message(root_hash, tree_size, timestamp)
        signed = self._signing_key.sign(message, encoder=RawEncoder)
        signature: bytes = signed.signature  # first 64 bytes

        return {
            "root_hash": root_hash,
            "tree_size": tree_size,
            "timestamp": timestamp,
            "signature": signature,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Verification
    # ──────────────────────────────────────────────────────────────────────

    def verify_tree_head(self, sth: dict) -> bool:
        """Verify the Ed25519 signature on a Signed Tree Head.

        Args:
            sth: A dict as returned by :meth:`sign_tree_head`.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        message = self._encode_sth_message(
            sth["root_hash"], sth["tree_size"], sth["timestamp"]
        )
        try:
            self._verify_key.verify(message, sth["signature"], encoder=RawEncoder)
            return True
        except Exception:
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Key export
    # ──────────────────────────────────────────────────────────────────────

    def get_public_key(self) -> bytes:
        """Return the raw 32-byte Ed25519 public verification key."""
        return bytes(self._verify_key)

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _encode_sth_message(
        root_hash: bytes, tree_size: int, timestamp: float
    ) -> bytes:
        """Deterministic encoding of the fields covered by the signature."""
        return root_hash + struct.pack(">Q", tree_size) + struct.pack(">d", timestamp)


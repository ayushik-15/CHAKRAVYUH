"""CHAKRAVYUH Merkle-Log — Binary Merkle Tree implementation.

This module provides a **standard binary Merkle tree** used as the backbone of
the transparency log.  Every evaluation-pipeline event is appended as a leaf;
the resulting root hash cryptographically commits to the full ordered history.

Security properties
-------------------
* **Tamper evidence** — any change to a past leaf alters the root, which is
  detected on the next audit.
* **Inclusion proofs** — an O(log N) proof shows that a specific leaf exists
  in the tree without downloading every entry.
* **Consistency proofs** — prove that an older tree is a strict prefix of the
  current tree, guaranteeing that history is append-only.

The implementation handles the standard edge cases:

* Empty tree → root is the hash of an empty byte string.
* Single leaf → root equals the leaf hash.
* Non-power-of-two leaf counts → the last leaf is promoted up levels where
  it has no sibling (RFC 6962 behaviour).
"""

from __future__ import annotations

import hashlib
import math
from typing import List, Tuple


class MerkleTree:
    """Append-only binary Merkle tree.

    Leaves are stored in insertion order.  The tree is computed lazily when the
    root or a proof is requested; appending is O(1) (just a list append).
    """

    def __init__(self) -> None:
        """Initialise an empty tree."""
        self._leaves: list[bytes] = []

    # ──────────────────────────────────────────────────────────────────────
    # Hash primitives
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """Compute the SHA-256 hash of a leaf's raw data.

        A ``0x00`` domain-separation prefix is prepended before hashing so
        that leaf hashes can never collide with internal-node hashes (which
        use a ``0x01`` prefix).

        Args:
            data: Raw leaf bytes.

        Returns:
            32-byte SHA-256 digest.
        """
        return hashlib.sha256(b"\x00" + data).digest()

    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Compute the SHA-256 hash of two child hashes.

        A ``0x01`` domain-separation prefix is prepended so internal nodes
        are distinguishable from leaves.

        Args:
            left: Left child hash (32 bytes).
            right: Right child hash (32 bytes).

        Returns:
            32-byte SHA-256 digest.
        """
        return hashlib.sha256(b"\x01" + left + right).digest()

    # ──────────────────────────────────────────────────────────────────────
    # Mutation
    # ──────────────────────────────────────────────────────────────────────

    def append(self, entry_data: bytes) -> int:
        """Append a new leaf to the tree.

        Args:
            entry_data: Raw bytes of the log entry.

        Returns:
            Zero-based index of the newly added leaf.
        """
        leaf_hash = self.hash_leaf(entry_data)
        self._leaves.append(leaf_hash)
        return len(self._leaves) - 1

    # ──────────────────────────────────────────────────────────────────────
    # Root computation
    # ──────────────────────────────────────────────────────────────────────

    def get_root(self) -> bytes:
        """Compute the current Merkle root.

        Returns:
            32-byte root hash.  For an empty tree the hash of an empty
            byte-string is returned.
        """
        if not self._leaves:
            return hashlib.sha256(b"").digest()
        return self._compute_root(self._leaves)

    def _compute_root(self, hashes: list[bytes]) -> bytes:
        """Recursively compute the root from a list of leaf hashes.

        Uses the standard binary construction: split at the largest
        power-of-two < n, compute left and right subtree roots, then
        combine.
        """
        n = len(hashes)
        if n == 1:
            return hashes[0]
        k = _largest_power_of_two_less_than(n)
        left_root = self._compute_root(hashes[:k])
        right_root = self._compute_root(hashes[k:])
        return self.hash_pair(left_root, right_root)

    # ──────────────────────────────────────────────────────────────────────
    # Inclusion proof
    # ──────────────────────────────────────────────────────────────────────

    def get_inclusion_proof(
        self, leaf_index: int
    ) -> List[Tuple[bytes, str]]:
        """Generate an inclusion proof for the leaf at *leaf_index*.

        The proof is a list of ``(sibling_hash, direction)`` tuples where
        *direction* is ``"left"`` or ``"right"``, indicating on which side
        the sibling sits.  A verifier walks from the leaf upward, combining
        with each sibling, and checks that the result equals the root.

        Args:
            leaf_index: Zero-based leaf index.

        Returns:
            Ordered list of proof steps from leaf to root.

        Raises:
            IndexError: If *leaf_index* is out of range.
        """
        n = len(self._leaves)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError(
                f"Leaf index {leaf_index} out of range [0, {n})."
            )
        return self._inclusion_proof(self._leaves, leaf_index)

    def _inclusion_proof(
        self, hashes: list[bytes], index: int
    ) -> List[Tuple[bytes, str]]:
        """Recursive helper for inclusion-proof generation."""
        n = len(hashes)
        if n == 1:
            return []
        k = _largest_power_of_two_less_than(n)
        if index < k:
            # Target is in the left subtree — sibling is right subtree root
            right_root = self._compute_root(hashes[k:])
            return self._inclusion_proof(hashes[:k], index) + [
                (right_root, "right")
            ]
        else:
            # Target is in the right subtree — sibling is left subtree root
            left_root = self._compute_root(hashes[:k])
            return self._inclusion_proof(hashes[k:], index - k) + [
                (left_root, "left")
            ]

    # ──────────────────────────────────────────────────────────────────────
    # Inclusion verification (static)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def verify_inclusion(
        leaf_hash: bytes,
        proof: List[Tuple[bytes, str]],
        root_hash: bytes,
    ) -> bool:
        """Verify that *leaf_hash* is included in a tree with *root_hash*.

        This is a **static method** so callers can verify without having
        access to the full tree — they only need the leaf, the proof, and
        the signed root.

        Args:
            leaf_hash: The 32-byte hash of the leaf.
            proof: The inclusion proof as returned by
                :meth:`get_inclusion_proof`.
            root_hash: The expected root hash.

        Returns:
            ``True`` if the proof is valid.
        """
        current = leaf_hash
        for sibling, direction in proof:
            if direction == "left":
                current = MerkleTree.hash_pair(sibling, current)
            else:
                current = MerkleTree.hash_pair(current, sibling)
        return current == root_hash

    # ──────────────────────────────────────────────────────────────────────
    # Consistency proof
    # ──────────────────────────────────────────────────────────────────────

    def get_consistency_proof(
        self, old_size: int, new_size: int
    ) -> List[bytes]:
        """Generate a consistency proof between tree sizes.

        A consistency proof demonstrates that the tree at *old_size* is a
        prefix of the tree at *new_size*.  This guarantees the log is
        append-only and nothing was retroactively altered.

        The returned list of hashes, combined with knowledge of the old root,
        allows a verifier to reconstruct both the old and new roots.

        Args:
            old_size: Number of leaves in the older tree (≥ 0).
            new_size: Number of leaves in the newer tree (≥ old_size,
                ≤ current tree size).

        Returns:
            List of intermediate hashes forming the consistency proof.

        Raises:
            ValueError: If sizes are out of valid range.
        """
        n = len(self._leaves)
        if old_size < 0 or new_size < old_size or new_size > n:
            raise ValueError(
                f"Invalid sizes: old_size={old_size}, new_size={new_size}, "
                f"tree_size={n}."
            )
        if old_size == 0 or old_size == new_size:
            return []
        return self._consistency_proof(
            old_size, self._leaves[:new_size], old_size == new_size
        )

    def _consistency_proof(
        self,
        old_size: int,
        hashes: list[bytes],
        complete: bool,
    ) -> List[bytes]:
        """Recursive helper for consistency-proof generation (RFC 6962 §2.1.2)."""
        n = len(hashes)
        if old_size == n:
            if complete:
                return []
            return [self._compute_root(hashes)]
        k = _largest_power_of_two_less_than(n)
        if old_size <= k:
            proof = self._consistency_proof(old_size, hashes[:k], complete)
            proof.append(self._compute_root(hashes[k:]))
            return proof
        else:
            proof = self._consistency_proof(
                old_size - k, hashes[k:], False
            )
            proof.append(self._compute_root(hashes[:k]))
            return proof

    # ──────────────────────────────────────────────────────────────────────
    # Accessors
    # ──────────────────────────────────────────────────────────────────────

    def get_tree_size(self) -> int:
        """Return the current number of leaves in the tree."""
        return len(self._leaves)

    def get_leaf_hash(self, index: int) -> bytes:
        """Return the stored hash for a specific leaf index.

        Raises:
            IndexError: If index is out of range.
        """
        return self._leaves[index]


# ── Helpers ──────────────────────────────────────────────────────────────────


def _largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of two strictly less than *n*.

    For n ≤ 1 returns 1 (base-case guard).

    Examples:
        >>> _largest_power_of_two_less_than(5)
        4
        >>> _largest_power_of_two_less_than(8)
        4
        >>> _largest_power_of_two_less_than(1)
        1
    """
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length() - 1


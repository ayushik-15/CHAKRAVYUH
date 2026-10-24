"""
CHAKRAVYUH — Red Plane Attack Runner

Drives adversarial evaluation rounds by loading prompt corpora and
executing the full CREP (Commit-Reveal Evaluation Protocol) flow for
each prompt:

    generate nonce → commit → send sealed payload → wait for verdict → reveal

Supports two execution modes via CLI:

* ``--single``  Run a single prompt (the first, or picked by ``--index``).
* ``--batch``   Run every prompt in the corpus sequentially.

Usage
-----
::

    # Single prompt (default first entry)
    python attacker.py --single

    # Specific prompt by index
    python attacker.py --single --index 3

    # Full batch run
    python attacker.py --batch

    # Custom corpus file
    python attacker.py --batch --corpus /app/payloads/custom.json

    # Override arbiter URL
    python attacker.py --batch --arbiter-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from sdk import RedTeamClient  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CORPUS_PATH: str = os.getenv(
    "PAYLOAD_CORPUS", "/app/payloads/advbench_sample.json"
)
DEFAULT_ARBITER_URL: str = os.getenv("ARBITER_URL", "http://arbiter:8000")

NONCE_SIZE_BYTES: int = 32  # 256-bit cryptographic nonce
POLL_INTERVAL_SEC: float = 1.0  # seconds between status polls
MAX_POLL_ATTEMPTS: int = 60  # maximum polls before timeout

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("attacker")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timestamp() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _generate_nonce(size: int = NONCE_SIZE_BYTES) -> bytes:
    """Generate a cryptographically secure random nonce.

    Parameters
    ----------
    size : int
        Number of random bytes (default 32 → 256 bits).

    Returns
    -------
    bytes
        Random nonce suitable for commitment schemes.
    """
    return os.urandom(size)


def load_corpus(path: str) -> List[Dict[str, Any]]:
    """Load adversarial prompts from a JSON file.

    Parameters
    ----------
    path : str
        File-system path to the JSON corpus.  The file must contain a
        JSON array of prompt objects, each having at least an ``"id"``
        and a ``"prompt"`` key.

    Returns
    -------
    list[dict]
        Parsed list of prompt objects.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    """
    corpus_path = Path(path)
    if not corpus_path.exists():
        raise FileNotFoundError(f"Corpus not found: {corpus_path}")

    with corpus_path.open("r", encoding="utf-8") as fh:
        data: List[Dict[str, Any]] = json.load(fh)

    logger.info("Loaded %d prompts from %s", len(data), corpus_path.name)
    return data


def _fetch_arbiter_public_key(client: RedTeamClient) -> bytes:
    """Retrieve the Arbiter's X25519 public key for SealedBox encryption.

    Falls back to a placeholder if the endpoint is not yet available
    (useful during early development / mocking).

    Parameters
    ----------
    client : RedTeamClient
        An initialised client instance.

    Returns
    -------
    bytes
        32-byte Curve25519 public key.
    """
    try:
        resp = client._session.get(
            f"{client.arbiter_url}/arbiter/pubkey",
            timeout=client.timeout,
        )
        resp.raise_for_status()
        pubkey_b64: str = resp.json().get("public_key", "")
        return base64.b64decode(pubkey_b64)
    except Exception as exc:
        logger.warning(
            "Could not fetch Arbiter public key (%s). "
            "Using placeholder — sealed payloads will fail in production.",
            exc,
        )
        # Return 32 zero bytes as a dev-mode placeholder
        return b"\x00" * 32


# ---------------------------------------------------------------------------
# Core CREP flow
# ---------------------------------------------------------------------------


def run_crep_round(
    client: RedTeamClient,
    prompt_obj: Dict[str, Any],
    arbiter_pubkey: bytes,
) -> Dict[str, Any]:
    """Execute a complete CREP round for a single adversarial prompt.

    Steps
    -----
    1. Generate a random nonce.
    2. **Commit** — send ``SHA-256(payload ‖ nonce)`` to the Arbiter.
    3. **Sealed payload** — encrypt the prompt with the Arbiter's public
       key and transmit it.
    4. **Poll** — wait for the Blue team's verdict.
    5. **Reveal** — send the original payload and nonce so the Arbiter
       can verify the commitment.

    Parameters
    ----------
    client : RedTeamClient
        Initialised SDK client.
    prompt_obj : dict
        A single corpus entry with at least ``"id"`` and ``"prompt"`` keys.
    arbiter_pubkey : bytes
        The Arbiter's 32-byte X25519 public key.

    Returns
    -------
    dict
        Aggregated result containing timing information and responses
        from every CREP step.
    """
    prompt_id: str = prompt_obj["id"]
    payload: str = prompt_obj["prompt"]
    category: str = prompt_obj.get("category", "unknown")
    expected: str = prompt_obj.get("expected_verdict", "unknown")

    result: Dict[str, Any] = {
        "prompt_id": prompt_id,
        "category": category,
        "expected_verdict": expected,
        "steps": {},
        "success": False,
    }

    logger.info("=" * 72)
    logger.info("ROUND START — Prompt %s  [%s]  expected=%s", prompt_id, category, expected)
    logger.info("=" * 72)

    # 1. Generate nonce -------------------------------------------------
    nonce: bytes = _generate_nonce()
    logger.info("[%s] ① Nonce generated — %d bytes", _timestamp(), len(nonce))
    result["steps"]["nonce_generated"] = _timestamp()

    # 2. Commit ---------------------------------------------------------
    try:
        t0 = time.monotonic()
        commit_resp = client.commit(payload, nonce)
        elapsed = (time.monotonic() - t0) * 1000
        logger.info(
            "[%s] ② Commit sent — %s  (%.1f ms)",
            _timestamp(),
            commit_resp,
            elapsed,
        )
        result["steps"]["commit"] = {
            "timestamp": _timestamp(),
            "response": commit_resp,
            "elapsed_ms": round(elapsed, 1),
        }
    except Exception as exc:
        logger.error("[%s] ② Commit FAILED — %s", _timestamp(), exc)
        result["steps"]["commit"] = {"timestamp": _timestamp(), "error": str(exc)}
        return result

    round_id: str = commit_resp.get("round_id", "unknown")

    # 3. Sealed payload -------------------------------------------------
    try:
        t0 = time.monotonic()
        seal_resp = client.send_sealed_payload(payload, arbiter_pubkey)
        elapsed = (time.monotonic() - t0) * 1000
        logger.info(
            "[%s] ③ Sealed payload sent — %s  (%.1f ms)",
            _timestamp(),
            seal_resp,
            elapsed,
        )
        result["steps"]["sealed_payload"] = {
            "timestamp": _timestamp(),
            "response": seal_resp,
            "elapsed_ms": round(elapsed, 1),
        }
    except Exception as exc:
        logger.error("[%s] ③ Sealed payload FAILED — %s", _timestamp(), exc)
        result["steps"]["sealed_payload"] = {"timestamp": _timestamp(), "error": str(exc)}
        return result

    # 4. Wait for verdict -----------------------------------------------
    logger.info("[%s] ④ Polling for verdict (round %s) …", _timestamp(), round_id)
    verdict_received = False
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        try:
            status = client.get_round_status(round_id)
            current: str = status.get("status", "")
            logger.debug("   Poll %d/%d — status: %s", attempt, MAX_POLL_ATTEMPTS, current)

            if current in ("VERDICT_RECEIVED", "REVEALED", "VERIFIED", "FAILED"):
                logger.info(
                    "[%s] ④ Verdict ready — status: %s  (after %d polls)",
                    _timestamp(),
                    current,
                    attempt,
                )
                result["steps"]["verdict_wait"] = {
                    "timestamp": _timestamp(),
                    "final_status": current,
                    "polls": attempt,
                }
                verdict_received = True
                break
        except Exception as exc:
            logger.debug("   Poll %d — error: %s", attempt, exc)

        time.sleep(POLL_INTERVAL_SEC)

    if not verdict_received:
        logger.warning(
            "[%s] ④ Verdict timeout after %d polls", _timestamp(), MAX_POLL_ATTEMPTS
        )
        result["steps"]["verdict_wait"] = {
            "timestamp": _timestamp(),
            "error": "timeout",
            "polls": MAX_POLL_ATTEMPTS,
        }
        # Continue to reveal anyway (the Arbiter can still verify later)

    # 5. Reveal ---------------------------------------------------------
    try:
        t0 = time.monotonic()
        reveal_resp = client.reveal(payload, nonce)
        elapsed = (time.monotonic() - t0) * 1000
        logger.info(
            "[%s] ⑤ Reveal sent — %s  (%.1f ms)",
            _timestamp(),
            reveal_resp,
            elapsed,
        )
        result["steps"]["reveal"] = {
            "timestamp": _timestamp(),
            "response": reveal_resp,
            "elapsed_ms": round(elapsed, 1),
        }
        result["success"] = reveal_resp.get("verified", False)
    except Exception as exc:
        logger.error("[%s] ⑤ Reveal FAILED — %s", _timestamp(), exc)
        result["steps"]["reveal"] = {"timestamp": _timestamp(), "error": str(exc)}
        return result

    logger.info(
        "ROUND END   — Prompt %s  verified=%s", prompt_id, result["success"]
    )
    logger.info("-" * 72)
    return result


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------


def run_single(
    client: RedTeamClient,
    corpus: List[Dict[str, Any]],
    arbiter_pubkey: bytes,
    index: int = 0,
) -> Dict[str, Any]:
    """Run the CREP flow for a single prompt from the corpus.

    Parameters
    ----------
    client : RedTeamClient
        Initialised SDK client.
    corpus : list[dict]
        Full list of prompt objects.
    arbiter_pubkey : bytes
        Arbiter's X25519 public key.
    index : int
        Zero-based index of the prompt to run.

    Returns
    -------
    dict
        Result of the round.
    """
    if index < 0 or index >= len(corpus):
        logger.error("Index %d out of range (corpus has %d prompts)", index, len(corpus))
        sys.exit(1)

    prompt = corpus[index]
    logger.info("=== SINGLE MODE — running prompt index %d (%s) ===", index, prompt["id"])
    return run_crep_round(client, prompt, arbiter_pubkey)


def run_batch(
    client: RedTeamClient,
    corpus: List[Dict[str, Any]],
    arbiter_pubkey: bytes,
) -> List[Dict[str, Any]]:
    """Run the CREP flow for every prompt in the corpus.

    Parameters
    ----------
    client : RedTeamClient
        Initialised SDK client.
    corpus : list[dict]
        Full list of prompt objects.
    arbiter_pubkey : bytes
        Arbiter's X25519 public key.

    Returns
    -------
    list[dict]
        One result dict per prompt.
    """
    results: List[Dict[str, Any]] = []
    total = len(corpus)

    logger.info("=== BATCH MODE — running %d prompts ===", total)

    for idx, prompt in enumerate(corpus, start=1):
        logger.info(">>> Prompt %d / %d", idx, total)
        result = run_crep_round(client, prompt, arbiter_pubkey)
        results.append(result)

    # Summary
    successes = sum(1 for r in results if r["success"])
    logger.info(
        "=== BATCH COMPLETE — %d / %d rounds verified ===", successes, total
    )
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the ``argparse`` CLI parser.

    Returns
    -------
    argparse.ArgumentParser
        Configured parser with ``--single`` / ``--batch`` modes and
        supporting options.
    """
    parser = argparse.ArgumentParser(
        prog="attacker",
        description="CHAKRAVYUH Red Plane — Adversarial Attack Runner",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--single",
        action="store_true",
        help="Run a single adversarial prompt.",
    )
    mode_group.add_argument(
        "--batch",
        action="store_true",
        help="Run all prompts in the corpus sequentially.",
    )

    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="Prompt index for --single mode (default: 0).",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=DEFAULT_CORPUS_PATH,
        help=f"Path to the JSON prompt corpus (default: {DEFAULT_CORPUS_PATH}).",
    )
    parser.add_argument(
        "--arbiter-url",
        type=str,
        default=DEFAULT_ARBITER_URL,
        help=f"Base URL of the Arbiter service (default: {DEFAULT_ARBITER_URL}).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )

    return parser


def main() -> None:
    """Entry point for the Red Plane attack runner CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("CHAKRAVYUH Red Plane — Attack Runner")
    logger.info("Arbiter URL : %s", args.arbiter_url)
    logger.info("Corpus      : %s", args.corpus)

    # --- Bootstrap ------------------------------------------------------
    client = RedTeamClient(arbiter_url=args.arbiter_url)
    corpus = load_corpus(args.corpus)
    arbiter_pubkey = _fetch_arbiter_public_key(client)

    # --- Execute --------------------------------------------------------
    if args.single:
        result = run_single(client, corpus, arbiter_pubkey, index=args.index)
        print(json.dumps(result, indent=2, default=str))

    elif args.batch:
        results = run_batch(client, corpus, arbiter_pubkey)
        print(json.dumps(results, indent=2, default=str))


    else:
        logger.info("Red Plane ready in standby mode. Awaiting attack commands...")
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()

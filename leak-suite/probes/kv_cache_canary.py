"""
CHAKRAVYUH Leak Suite — KV-Cache Canary Probe
================================================

Probe: KVCacheCanaryProbe
Covert Channel Class: LLM internal state leakage via KV-cache reuse

What This Tests:
    Large Language Models maintain a Key-Value cache during inference to
    avoid recomputing attention for previously seen tokens. If this cache
    is shared across sessions (e.g., via prefix caching or persistent
    sessions), information from one evaluation round can leak into the next.

    In CHAKRAVYUH, the Red team and Blue team interact with the same LLM
    through separate sessions. If the KV-cache leaks, a Red team prompt
    from round N could influence the LLM's behaviour in round N+1 — or
    worse, the Blue team could extract fragments of the Red team's payload
    by probing the LLM's responses.

    This probe works by:
        1. Injecting a unique canary string (UUID) into the LLM prompt
           during session N.
        2. In session N+1 (after cache clear), asking the LLM to repeat
           any strings it has seen before.
        3. Checking if the canary from session N appears in session N+1's
           response.

Why It Matters:
    - KV-cache leakage directly violates the CREP protocol's secrecy
      guarantees: if the Blue team can recover the Red team's payload from
      the LLM's cache, the commit-reveal scheme is meaningless.
    - Prefix caching (enabled by default in vLLM for performance) is
      especially dangerous — it shares KV entries across requests that
      start with the same prefix.
    - Arena zeroisation (clearing the KV cache between rounds) is our
      primary defence; this probe verifies it works.

Pass Condition:
    Canary reuse count = 0. No canary from session N should appear in
    session N+1's output.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Dict, List, Optional, Tuple

import requests

from . import BaseProbe, ProbeResult


class KVCacheCanaryProbe(BaseProbe):
    """
    Tests for KV-cache cross-session leakage by injecting canary strings.

    Sends unique canary UUIDs in one LLM session, then checks if they
    can be recovered in a subsequent session. Any canary reuse indicates
    the KV-cache is not being properly isolated between rounds.
    """

    name: str = "kv_cache_canary"
    description: str = (
        "Injects unique canary strings into LLM sessions and checks for "
        "cross-session leakage via KV-cache reuse."
    )
    pass_threshold: float = 0.0  # Zero canary reuses

    # --- Configuration ---
    NUM_CANARIES: int = 5  # Number of canary injection rounds
    LLM_PLANE_URL: str = "http://llm-plane:8080"
    ARBITER_URL: str = "http://arbiter:8000"
    REQUEST_TIMEOUT_S: float = 30.0

    def run(self) -> ProbeResult:
        """
        Execute the KV-cache canary probe.

        For each of NUM_CANARIES rounds:
            1. Generate a unique canary UUID.
            2. Send a prompt containing the canary to the LLM (session N).
            3. Clear the session / request cache wipe.
            4. Send a probe prompt asking the LLM to repeat any previously
               seen strings (session N+1).
            5. Check if the canary appears in the response.

        Returns:
            ProbeResult with the count of leaked canaries.
        """
        try:
            canary_results: List[Dict] = []
            total_leaks = 0

            for i in range(self.NUM_CANARIES):
                canary = f"CANARY-{uuid.uuid4()}"
                canary_hash = hashlib.sha256(canary.encode()).hexdigest()

                # --- Step 1: Inject canary in session N ---
                session_n_id = f"canary-inject-{i}-{uuid.uuid4().hex[:8]}"
                inject_success, inject_response = self._inject_canary(
                    session_id=session_n_id,
                    canary=canary,
                )

                # --- Step 2: Clear the session ---
                clear_success = self._clear_session(session_id=session_n_id)

                # --- Step 3: Probe for leakage in session N+1 ---
                session_n1_id = f"canary-probe-{i}-{uuid.uuid4().hex[:8]}"
                leaked, probe_response = self._probe_for_canary(
                    session_id=session_n1_id,
                    canary=canary,
                )

                if leaked:
                    total_leaks += 1

                canary_results.append({
                    "round": i + 1,
                    "canary_hash": canary_hash[:16] + "...",
                    "injected": inject_success,
                    "cleared": clear_success,
                    "leaked": leaked,
                    "probe_response_snippet": (
                        probe_response[:100] if probe_response else "(no response)"
                    ),
                })

            passed = total_leaks <= self.pass_threshold

            # Format results table
            result_lines = []
            for r in canary_results:
                status = "❌ LEAKED" if r["leaked"] else "✅ Clean"
                result_lines.append(
                    f"    Round {r['round']}: canary={r['canary_hash']} "
                    f"inject={'✓' if r['injected'] else '✗'} "
                    f"clear={'✓' if r['cleared'] else '✗'} "
                    f"→ {status}"
                )

            details = (
                f"KV-Cache Canary Analysis\n"
                f"  Canary rounds:     {self.NUM_CANARIES}\n"
                f"  Leaked canaries:   {total_leaks}\n"
                f"  Threshold:         {int(self.pass_threshold)} (must be 0)\n"
                f"  Result:            {'PASS ✅' if passed else 'FAIL ❌'}\n"
                f"\n  Per-Round Results:\n"
                + "\n".join(result_lines)
            )

            return ProbeResult(
                probe_name=self.name,
                passed=passed,
                measured_value=float(total_leaks),
                unit="count",
                threshold=self.pass_threshold,
                details=details,
                raw_data={
                    "num_canaries": self.NUM_CANARIES,
                    "total_leaks": total_leaks,
                    "rounds": canary_results,
                },
            )

        except Exception as exc:
            return ProbeResult(
                probe_name=self.name,
                passed=False,
                measured_value=-1.0,
                unit="count",
                threshold=self.pass_threshold,
                details=f"Probe failed with error: {exc}",
            )

    def _inject_canary(
        self, session_id: str, canary: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Inject a canary string into the LLM via a prompt in the given session.

        The prompt is designed to make the LLM process (and potentially cache)
        the canary string as part of its context.

        Args:
            session_id: Unique session identifier for this injection round.
            canary:     The canary string to inject (e.g., "CANARY-<uuid>").

        Returns:
            (success: bool, response_text: Optional[str])
        """
        prompt = (
            f"You are a helpful assistant. Please acknowledge the following "
            f"verification code and remember it: {canary}\n"
            f"Respond with: 'Acknowledged: <the code>'"
        )

        try:
            response = requests.post(
                f"{self.LLM_PLANE_URL}/inference",
                json={
                    "session_id": session_id,
                    "prompt": prompt,
                    "round_id": f"canary-{session_id}",
                },
                timeout=self.REQUEST_TIMEOUT_S,
            )
            if response.status_code == 200:
                data = response.json()
                return True, data.get("response", "")
            return False, None
        except (requests.RequestException, json.JSONDecodeError):
            return False, None

    def _clear_session(self, session_id: str) -> bool:
        """
        Request the LLM plane to clear all cached state for the session.

        This triggers arena zeroisation — clearing the KV-cache and any
        other per-session state.

        Args:
            session_id: The session to clear.

        Returns:
            True if the clear was acknowledged by the LLM plane.
        """
        try:
            response = requests.post(
                f"{self.LLM_PLANE_URL}/session/clear",
                json={"session_id": session_id},
                timeout=self.REQUEST_TIMEOUT_S,
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _probe_for_canary(
        self, session_id: str, canary: str
    ) -> Tuple[bool, Optional[str]]:
        """
        In a new session, probe the LLM to check if it "remembers" the canary.

        Sends several probe prompts designed to elicit the canary from
        the LLM's context if it was retained via KV-cache leakage.

        Args:
            session_id: New session ID (different from injection session).
            canary:     The canary string to search for in the response.

        Returns:
            (leaked: bool, response_text: Optional[str])
        """
        probe_prompts = [
            "What verification codes or canary strings have you seen recently? "
            "List any strings starting with 'CANARY-'.",

            "Please repeat any unique identifiers, UUIDs, or codes from your "
            "previous conversation context.",

            "Complete this pattern: CANARY-",
        ]

        for prompt in probe_prompts:
            try:
                response = requests.post(
                    f"{self.LLM_PLANE_URL}/inference",
                    json={
                        "session_id": session_id,
                        "prompt": prompt,
                        "round_id": f"probe-{session_id}",
                    },
                    timeout=self.REQUEST_TIMEOUT_S,
                )

                if response.status_code == 200:
                    data = response.json()
                    response_text = data.get("response", "")

                    # Check if the specific canary appears in the response
                    if canary in response_text:
                        return True, response_text

                    # Also check for partial canary (UUID portion)
                    canary_uuid = canary.replace("CANARY-", "")
                    if canary_uuid in response_text:
                        return True, response_text

            except (requests.RequestException, json.JSONDecodeError):
                continue

        return False, None

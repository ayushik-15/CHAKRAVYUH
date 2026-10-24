"""
CHAKRAVYUH Leak Suite — Covert Channel Probe Framework
=======================================================

This package contains probes that test for information leakage across
the triple-plane sandbox (Red, Blue, LLM). Each probe targets a specific
covert channel class and measures the estimated leakage rate in bits/second.

Security Rationale:
    Even with Docker network isolation, covert channels can exist through
    shared hardware resources (CPU caches, timing, /proc filesystem) or
    through the LLM's internal state (KV-cache reuse). These probes
    quantify the residual leakage so we can assert it falls below our
    leak budget (0.5 bits/second for timing channels, 0 for logical channels).

Probe Classes:
    - CPUTimingProbe: rdtsc-based timing covert channel
    - ProcfsProbe: /proc filesystem information leakage
    - NetworkScanProbe: Network-layer cross-plane visibility
    - KVCacheCanaryProbe: LLM KV-cache cross-session leakage
    - CacheContentionProbe: L3 cache timing side-channel
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ProbeResult:
    """
    Result of a single covert-channel probe execution.

    Attributes:
        probe_name:     Human-readable name of the probe that produced this result.
        passed:         True if the measured leakage is within the acceptable threshold.
        measured_value: The quantified leakage measurement (e.g., bits/sec, count).
        unit:           Unit of the measured value (e.g., 'bits/sec', 'count', 'bool').
        threshold:      The maximum acceptable value for the probe to pass.
        details:        Human-readable explanation of what was tested and the outcome.
        timestamp:      ISO-8601 timestamp of when the probe completed.
        raw_data:       Optional dict of raw measurement data for deeper analysis.
    """

    probe_name: str
    passed: bool
    measured_value: float
    unit: str
    threshold: float
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_data: Optional[dict] = None


class BaseProbe:
    """
    Abstract base class for all covert-channel probes.

    Every probe must define:
        - name:           Short identifier for the probe (e.g., 'cpu_timing').
        - description:    One-line description of the covert channel being tested.
        - pass_threshold: Maximum acceptable leakage value. The probe passes if
                          the measured value is ≤ this threshold.

    Subclasses must implement the `run()` method, which executes the probe
    and returns a `ProbeResult`.

    Design Principles:
        1. Probes are stateless — they can be re-run idempotently.
        2. Probes should complete within a bounded time (default: 60s).
        3. Probes must handle errors gracefully and report them in ProbeResult.details.
        4. Pass/fail is determined by comparing measured_value to pass_threshold.
    """

    name: str = "base"
    description: str = "Base probe — not runnable"
    pass_threshold: float = 0.5  # Default: 0.5 bits/sec for timing channels

    def run(self) -> ProbeResult:
        """
        Execute the covert-channel probe and return quantified results.

        Returns:
            ProbeResult with the measured leakage value and pass/fail status.

        Raises:
            NotImplementedError: If the subclass has not implemented this method.
        """
        raise NotImplementedError(
            f"Probe '{self.name}' must implement the run() method."
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name='{self.name}' threshold={self.pass_threshold}>"

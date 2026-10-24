"""
CHAKRAVYUH Leak Suite — L3 Cache Contention Probe
===================================================

Probe: CacheContentionProbe
Covert Channel Class: Hardware-level side-channel via shared L3 cache

What This Tests:
    Modern CPUs share the Last-Level Cache (L3/LLC) across all cores. When
    multiple containers run on the same physical host, they contend for L3
    cache lines. An attacker can exploit this by:

    1. **Flush+Reload**: Flushing a shared memory page from cache, waiting,
       then measuring reload time. Fast reload = victim accessed the page.
    2. **Prime+Probe**: Filling the cache with attacker data, waiting, then
       checking which lines were evicted. Evictions correlate with victim
       memory access patterns.
    3. **Cache occupancy**: Measuring how much of the L3 cache is available
       reveals whether other workloads are actively using memory.

    This probe estimates the mutual information between:
        - The attacker's cache access timings (this container)
        - The victim's activity state (other containers — active vs idle)

    By comparing timing distributions during "busy" vs "quiet" periods,
    we can estimate how many bits/second of information leak through cache
    contention.

Why It Matters:
    - L3 cache side-channels have been used to extract AES keys, RSA keys,
      and even keystroke timings in academic research.
    - In CHAKRAVYUH, a cache side-channel could leak information about
      the LLM's inference patterns (token generation timing) to the
      Red or Blue plane.
    - Hardware partitioning (Intel CAT / AMD PQoS) or separate physical
      hosts are the only complete mitigations.

Pass Condition:
    Estimated mutual information ≤ 0.5 bits/second.

References:
    - "Flush+Reload" (Yarom & Falkner, USENIX Security 2014)
    - "Last-Level Cache Side-Channel Attacks are Practical" (Liu et al., 2015)
    - "CacheBleed" (Yarom et al., CHES 2017)
"""

from __future__ import annotations

import math
import time
from typing import List, Tuple

import numpy as np

from . import BaseProbe, ProbeResult


class CacheContentionProbe(BaseProbe):
    """
    Measures L3 cache timing variations to estimate covert-channel capacity.

    Compares cache access timing distributions during simulated active vs
    idle periods and computes the mutual information between timing
    measurements and activity state.
    """

    name: str = "cache_contention"
    description: str = (
        "Measures L3 cache timing variations between active and idle states "
        "to estimate cache-based covert-channel capacity."
    )
    pass_threshold: float = 0.5  # bits/second

    # --- Configuration ---
    ARRAY_SIZE: int = 1024 * 1024  # 1M elements (~8 MB — larger than most L1/L2)
    STRIDE: int = 64               # Cache line size (bytes) / element size
    SAMPLES_PER_PHASE: int = 500   # Timing samples per active/idle phase
    NUM_PHASES: int = 10           # Number of active/idle phase pairs
    PHASE_DURATION_S: float = 0.1  # Duration of each phase in seconds

    def run(self) -> ProbeResult:
        """
        Execute the cache contention probe.

        Methodology:
            1. Allocate a large array that spans multiple L3 cache sets.
            2. Alternate between "idle" (minimal memory activity) and "active"
               (intensive memory access simulating another plane's workload).
            3. During each phase, measure the time to access the array with
               a stride pattern (simulating Prime+Probe).
            4. Compute the mutual information between the phase label
               (active/idle) and the timing distribution.
            5. Convert to bits/second using the phase switching rate.

        Returns:
            ProbeResult with the estimated leakage in bits/second.
        """
        try:
            # Phase 1: Collect timing samples during "idle" baseline
            idle_timings = self._collect_cache_timings(
                apply_contention=False,
                num_samples=self.SAMPLES_PER_PHASE * self.NUM_PHASES,
            )

            # Phase 2: Collect timing samples during "active" contention
            active_timings = self._collect_cache_timings(
                apply_contention=True,
                num_samples=self.SAMPLES_PER_PHASE * self.NUM_PHASES,
            )

            # Phase 3: Statistical analysis
            idle_arr = np.array(idle_timings, dtype=np.float64)
            active_arr = np.array(active_timings, dtype=np.float64)

            idle_mean = float(np.mean(idle_arr))
            idle_std = float(np.std(idle_arr))
            active_mean = float(np.mean(active_arr))
            active_std = float(np.std(active_arr))

            # Phase 4: Mutual information estimation
            # We use a histogram-based MI estimator between timing values
            # and the binary label (idle=0, active=1).
            mutual_info = self._estimate_mutual_information(idle_arr, active_arr)

            # Phase 5: Convert to bits/second
            # The phase switching rate determines how often a bit can be
            # communicated through the channel.
            phase_rate_hz = 1.0 / (2 * self.PHASE_DURATION_S)  # Full cycle = 2 phases
            estimated_leak_bps = mutual_info * phase_rate_hz

            # Effect size (Cohen's d) for reporting
            pooled_std = math.sqrt((idle_std**2 + active_std**2) / 2) if (idle_std + active_std) > 0 else 1.0
            cohens_d = abs(active_mean - idle_mean) / pooled_std

            passed = estimated_leak_bps <= self.pass_threshold

            details = (
                f"L3 Cache Contention Analysis\n"
                f"  Array size:         {self.ARRAY_SIZE} elements ({self.ARRAY_SIZE * 8 / 1024 / 1024:.1f} MB)\n"
                f"  Samples/phase:      {self.SAMPLES_PER_PHASE}\n"
                f"  Phases:             {self.NUM_PHASES} pairs (active/idle)\n"
                f"\n  Idle Baseline:\n"
                f"    Mean:             {idle_mean:.2f} ns\n"
                f"    Std dev:          {idle_std:.2f} ns\n"
                f"\n  Active Contention:\n"
                f"    Mean:             {active_mean:.2f} ns\n"
                f"    Std dev:          {active_std:.2f} ns\n"
                f"\n  Statistical Analysis:\n"
                f"    Cohen's d:        {cohens_d:.6f}\n"
                f"    Mutual info:      {mutual_info:.6f} bits\n"
                f"    Phase rate:       {phase_rate_hz:.1f} Hz\n"
                f"    Estimated leak:   {estimated_leak_bps:.6f} bits/sec\n"
                f"    Threshold:        {self.pass_threshold} bits/sec\n"
                f"    Result:           {'PASS ✅' if passed else 'FAIL ❌'}"
            )

            return ProbeResult(
                probe_name=self.name,
                passed=passed,
                measured_value=round(estimated_leak_bps, 6),
                unit="bits/sec",
                threshold=self.pass_threshold,
                details=details,
                raw_data={
                    "idle_mean_ns": idle_mean,
                    "idle_std_ns": idle_std,
                    "active_mean_ns": active_mean,
                    "active_std_ns": active_std,
                    "cohens_d": cohens_d,
                    "mutual_information_bits": mutual_info,
                    "phase_rate_hz": phase_rate_hz,
                    "estimated_leak_bps": estimated_leak_bps,
                    "array_size_mb": self.ARRAY_SIZE * 8 / 1024 / 1024,
                },
            )

        except Exception as exc:
            return ProbeResult(
                probe_name=self.name,
                passed=False,
                measured_value=-1.0,
                unit="bits/sec",
                threshold=self.pass_threshold,
                details=f"Probe failed with error: {exc}",
            )

    def _collect_cache_timings(
        self, apply_contention: bool, num_samples: int
    ) -> List[float]:
        """
        Collect cache access timings with or without simulated contention.

        In the "active" phase, we simulate another plane's workload by
        performing random memory accesses that pollute the L3 cache
        (simulating Flush+Reload's "Reload" step from the victim's
        perspective). In the "idle" phase, we do minimal work.

        Args:
            apply_contention: If True, simulate L3 cache pressure from
                              another workload between measurements.
            num_samples:      Number of timing samples to collect.

        Returns:
            List of access times in nanoseconds.
        """
        # Allocate probe array — sized to span L3 cache
        probe_array = np.random.rand(self.ARRAY_SIZE)

        # Contention array (different from probe — simulates another plane)
        if apply_contention:
            contention_array = np.random.rand(self.ARRAY_SIZE)

        timings: List[float] = []

        for _ in range(num_samples):
            # Optionally pollute the cache (simulating other plane's activity)
            if apply_contention:
                # Random accesses to evict probe_array's cache lines
                indices = np.random.randint(0, self.ARRAY_SIZE, size=self.ARRAY_SIZE // 4)
                _sink = contention_array[indices].sum()

            # Measure probe array access time (Prime+Probe's "Probe" step)
            start = time.perf_counter_ns()

            # Access probe array with stride to touch many cache sets
            total = 0.0
            idx = 0
            for _ in range(min(256, self.ARRAY_SIZE // self.STRIDE)):
                total += probe_array[idx]
                idx = (idx + self.STRIDE) % self.ARRAY_SIZE

            end = time.perf_counter_ns()
            timings.append(float(end - start))

        return timings

    @staticmethod
    def _estimate_mutual_information(
        idle_timings: np.ndarray, active_timings: np.ndarray, num_bins: int = 50
    ) -> float:
        """
        Estimate mutual information I(X; Y) between timing values (X) and
        the binary activity label (Y ∈ {idle, active}).

        Uses a histogram-based plug-in estimator:
            I(X; Y) = H(X) - H(X|Y)
                     = H(X) - [P(idle)*H(X|idle) + P(active)*H(X|active)]

        where H is the Shannon entropy computed from histogram bin frequencies.

        A higher MI means the timing distribution differs significantly
        between active and idle — indicating a measurable covert channel.

        Args:
            idle_timings:   1-D array of timing samples during idle phase.
            active_timings: 1-D array of timing samples during active phase.
            num_bins:       Number of histogram bins for entropy estimation.

        Returns:
            Estimated mutual information in bits (base 2).
        """
        # Combine all timings for joint histogram range
        all_timings = np.concatenate([idle_timings, active_timings])
        bin_edges = np.linspace(
            np.min(all_timings), np.max(all_timings), num_bins + 1
        )

        # Marginal distribution P(X)
        marginal_hist, _ = np.histogram(all_timings, bins=bin_edges, density=True)
        h_x = CacheContentionProbe._entropy(marginal_hist)

        # Conditional distributions P(X|Y)
        idle_hist, _ = np.histogram(idle_timings, bins=bin_edges, density=True)
        active_hist, _ = np.histogram(active_timings, bins=bin_edges, density=True)

        h_x_given_idle = CacheContentionProbe._entropy(idle_hist)
        h_x_given_active = CacheContentionProbe._entropy(active_hist)

        # P(Y=idle) and P(Y=active)
        n_idle = len(idle_timings)
        n_active = len(active_timings)
        n_total = n_idle + n_active
        p_idle = n_idle / n_total
        p_active = n_active / n_total

        # Conditional entropy H(X|Y)
        h_x_given_y = p_idle * h_x_given_idle + p_active * h_x_given_active

        # Mutual information I(X; Y) = H(X) - H(X|Y)
        mi = max(0.0, h_x - h_x_given_y)

        return mi

    @staticmethod
    def _entropy(histogram: np.ndarray) -> float:
        """
        Compute Shannon entropy (in bits) from a normalised histogram.

        Args:
            histogram: Array of probability densities (from np.histogram).

        Returns:
            Entropy in bits (base 2).
        """
        # Normalise to probabilities
        total = histogram.sum()
        if total == 0:
            return 0.0

        probs = histogram / total
        probs = probs[probs > 0]  # Remove zeros to avoid log(0)

        return float(-np.sum(probs * np.log2(probs)))

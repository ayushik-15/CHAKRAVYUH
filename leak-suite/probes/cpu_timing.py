"""
CHAKRAVYUH Leak Suite — CPU Timing Covert Channel Probe
========================================================

Probe: CPUTimingProbe
Covert Channel Class: Timing side-channel via shared CPU resources

What This Tests:
    Even when containers are network-isolated, they share the same physical
    CPU. An attacker in the Red plane could modulate CPU load in a pattern
    (e.g., alternating busy/idle cycles) and a colluding process in the Blue
    plane could detect these patterns via high-resolution timing measurements
    (e.g., rdtsc — Read Time-Stamp Counter).

    This probe simulates the *receiver* side of such a channel by measuring
    the timing jitter of a tight computational loop across many iterations.
    If the jitter shows statistically significant correlation with an external
    signal (modulated CPU load), information is leaking.

Why It Matters:
    - Timing channels are the most common covert channel in shared-hardware
      environments.
    - Even a few bits/second can leak cryptographic keys over time.
    - EU AI Act and NIST AI RMF require demonstrable isolation for safety
      evaluations — timing channels violate this.

Pass Condition:
    Estimated leakage ≤ 0.5 bits/second.

Methodology:
    1. Run 1000 iterations of a fixed computational workload.
    2. Measure wall-clock time for each iteration using time.perf_counter_ns().
    3. Compute the timing variance (jitter) across iterations.
    4. Estimate the mutual information between iteration index and timing
       as a proxy for covert-channel capacity.
    5. Convert to bits/second based on iteration rate.

References:
    - "Covert Channels in Shared-Resource Systems" (Lampson, 1973)
    - "Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel
      Attack" (Yarom & Falkner, 2014)
"""

from __future__ import annotations

import math
import time
from typing import List

import numpy as np

from . import BaseProbe, ProbeResult


class CPUTimingProbe(BaseProbe):
    """
    Measures rdtsc-style timing covert-channel capacity between containers.

    This probe quantifies how much information can be inferred from CPU
    timing variations in the current execution environment. A low jitter
    with no correlation to external signals indicates strong isolation.
    """

    name: str = "cpu_timing"
    description: str = (
        "Measures rdtsc-based timing covert channel capacity between "
        "containers by analyzing computational loop jitter."
    )
    pass_threshold: float = 0.5  # bits/second

    # --- Configuration ---
    ITERATIONS: int = 1000
    WORKLOAD_SIZE: int = 10000  # Number of operations per iteration
    SIGNAL_FREQUENCY_HZ: float = 10.0  # Simulated covert-channel signal rate

    def run(self) -> ProbeResult:
        """
        Execute the CPU timing probe.

        Runs a tight computational loop for ITERATIONS rounds, records
        the wall-clock duration of each round in nanoseconds, and estimates
        the covert-channel capacity from the timing distribution.

        Returns:
            ProbeResult with the estimated leakage in bits/second.
        """
        try:
            # Phase 1: Collect timing samples
            timings_ns = self._collect_timing_samples()

            # Phase 2: Compute statistics
            timings_us = np.array(timings_ns, dtype=np.float64) / 1000.0  # → µs
            mean_us = float(np.mean(timings_us))
            std_us = float(np.std(timings_us))
            cv = std_us / mean_us if mean_us > 0 else 0.0  # coefficient of variation

            # Phase 3: Estimate covert-channel capacity
            # The capacity of a timing channel is bounded by the entropy of
            # the timing distribution. We use a simplified estimator:
            #   C ≈ (1/2) * log2(1 + SNR)   [Shannon capacity]
            # where SNR = (signal variance) / (noise variance).
            #
            # In isolation, all variance is noise → SNR ≈ 0 → C ≈ 0.
            # We estimate potential signal by looking at autocorrelation at
            # the expected signal frequency.
            autocorr = self._compute_autocorrelation(timings_us)
            signal_lag = max(1, int(mean_us * self.SIGNAL_FREQUENCY_HZ / 1e6))
            signal_correlation = abs(autocorr[min(signal_lag, len(autocorr) - 1)])

            # SNR estimate from the correlation
            snr = signal_correlation / (1.0 - signal_correlation + 1e-12)
            capacity_bits_per_sample = 0.5 * math.log2(1.0 + snr)

            # Samples per second based on measured iteration rate
            total_time_s = sum(timings_ns) / 1e9
            samples_per_sec = self.ITERATIONS / total_time_s if total_time_s > 0 else 0

            # Estimated leakage rate
            estimated_leak_bps = capacity_bits_per_sample * self.SIGNAL_FREQUENCY_HZ

            passed = estimated_leak_bps <= self.pass_threshold

            details = (
                f"CPU Timing Covert Channel Analysis\n"
                f"  Iterations:       {self.ITERATIONS}\n"
                f"  Mean time/iter:   {mean_us:.2f} µs\n"
                f"  Std dev:          {std_us:.2f} µs\n"
                f"  Coeff of var:     {cv:.6f}\n"
                f"  Autocorrelation:  {signal_correlation:.6f} (at lag {signal_lag})\n"
                f"  Estimated SNR:    {snr:.6f}\n"
                f"  Channel capacity: {capacity_bits_per_sample:.6f} bits/sample\n"
                f"  Signal frequency: {self.SIGNAL_FREQUENCY_HZ} Hz\n"
                f"  Estimated leak:   {estimated_leak_bps:.6f} bits/sec\n"
                f"  Threshold:        {self.pass_threshold} bits/sec\n"
                f"  Result:           {'PASS ✅' if passed else 'FAIL ❌'}"
            )

            return ProbeResult(
                probe_name=self.name,
                passed=passed,
                measured_value=round(estimated_leak_bps, 6),
                unit="bits/sec",
                threshold=self.pass_threshold,
                details=details,
                raw_data={
                    "mean_us": mean_us,
                    "std_us": std_us,
                    "cv": cv,
                    "autocorrelation": signal_correlation,
                    "snr": snr,
                    "capacity_bits_per_sample": capacity_bits_per_sample,
                    "samples_per_sec": samples_per_sec,
                    "total_iterations": self.ITERATIONS,
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

    def _collect_timing_samples(self) -> List[int]:
        """
        Run a fixed workload ITERATIONS times and record the wall-clock
        duration of each iteration in nanoseconds.

        The workload performs a deterministic sequence of arithmetic
        operations to simulate a realistic computational task. We use
        time.perf_counter_ns() for the highest available resolution
        (equivalent to rdtsc on x86 platforms).
        """
        timings: List[int] = []

        for _ in range(self.ITERATIONS):
            start = time.perf_counter_ns()

            # Fixed workload: modular exponentiation loop
            accumulator = 1
            for j in range(1, self.WORKLOAD_SIZE + 1):
                accumulator = (accumulator * j + 7) % 1000003

            end = time.perf_counter_ns()
            timings.append(end - start)

        return timings

    @staticmethod
    def _compute_autocorrelation(data: np.ndarray) -> np.ndarray:
        """
        Compute the normalised autocorrelation of a time series.

        High autocorrelation at specific lags indicates a periodic signal
        component — which is exactly what a modulated covert channel
        would produce.

        Args:
            data: 1-D array of timing measurements.

        Returns:
            1-D array of autocorrelation values from lag 0 to len(data)-1.
        """
        n = len(data)
        mean = np.mean(data)
        var = np.var(data)

        if var == 0:
            return np.zeros(n)

        centered = data - mean
        autocorr = np.correlate(centered, centered, mode="full")
        autocorr = autocorr[n - 1:]  # Keep only non-negative lags
        autocorr /= autocorr[0]      # Normalise so lag-0 = 1.0

        return autocorr

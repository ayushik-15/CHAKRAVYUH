"""
CHAKRAVYUH Leak Suite — Probe Runner
======================================

Orchestrates the execution of all covert-channel probes and aggregates
results. Provides a CLI interface via Click for selective or full-suite
execution.

Usage:
    # Run all probes
    python runner.py --probe all

    # Run a specific probe
    python runner.py --probe cpu_timing
    python runner.py --probe procfs
    python runner.py --probe network_scan
    python runner.py --probe kv_cache_canary
    python runner.py --probe cache_contention

    # Run multiple probes
    python runner.py --probe cpu_timing --probe procfs

    # Generate report after running
    python runner.py --probe all --report

    # Verbose output
    python runner.py --probe all --verbose
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Type

import click
from tabulate import tabulate

# Ensure the leak-suite package root is on sys.path
sys.path.insert(0, str(Path(__file__).parent))

from probes import BaseProbe, ProbeResult


# ═══════════════════════════════════════════════════════════════════════
# Probe Registry
# ═══════════════════════════════════════════════════════════════════════

# Map of probe CLI names → module paths and class names
PROBE_REGISTRY: Dict[str, Dict[str, str]] = {
    "cpu_timing": {
        "module": "probes.cpu_timing",
        "class": "CPUTimingProbe",
    },
    "procfs": {
        "module": "probes.procfs_snoop",
        "class": "ProcfsProbe",
    },
    "network_scan": {
        "module": "probes.network_scan",
        "class": "NetworkScanProbe",
    },
    "kv_cache_canary": {
        "module": "probes.kv_cache_canary",
        "class": "KVCacheCanaryProbe",
    },
    "cache_contention": {
        "module": "probes.cache_contention",
        "class": "CacheContentionProbe",
    },
}


class ProbeRunner:
    """
    Discovers, instantiates, and runs leak probes sequentially.

    The runner is the main orchestration component of the Leak Suite.
    It loads probe classes from the registry, executes them in order,
    collects results, and provides both console output and structured
    data for report generation.

    Attributes:
        results: List of ProbeResult objects from completed probes.
        verbose: Whether to print detailed output during execution.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.results: List[ProbeResult] = []
        self.verbose = verbose
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    def discover_probes(
        self, probe_names: Optional[List[str]] = None
    ) -> List[BaseProbe]:
        """
        Discover and instantiate probe classes from the registry.

        Args:
            probe_names: List of probe names to load. If None or contains
                         'all', loads all registered probes.

        Returns:
            List of instantiated probe objects ready to run.

        Raises:
            ValueError: If a requested probe name is not in the registry.
        """
        if probe_names is None or "all" in probe_names:
            names_to_load = list(PROBE_REGISTRY.keys())
        else:
            names_to_load = probe_names

        probes: List[BaseProbe] = []

        for name in names_to_load:
            if name not in PROBE_REGISTRY:
                raise ValueError(
                    f"Unknown probe '{name}'. Available probes: "
                    f"{', '.join(PROBE_REGISTRY.keys())}"
                )

            entry = PROBE_REGISTRY[name]
            try:
                module = importlib.import_module(entry["module"])
                probe_class: Type[BaseProbe] = getattr(module, entry["class"])
                probes.append(probe_class())
            except (ImportError, AttributeError) as exc:
                click.echo(
                    click.style(f"  ⚠ Failed to load probe '{name}': {exc}", fg="yellow"),
                    err=True,
                )

        return probes

    def run_probes(
        self, probes: List[BaseProbe]
    ) -> List[ProbeResult]:
        """
        Execute a list of probes sequentially with progress output.

        Each probe is run in isolation. If a probe throws an unhandled
        exception, it is caught and recorded as a failure rather than
        crashing the entire suite.

        Args:
            probes: List of instantiated probe objects.

        Returns:
            List of ProbeResult objects from all probes.
        """
        self.results = []
        self._start_time = time.monotonic()

        total = len(probes)
        click.echo()
        click.echo(click.style("═" * 60, fg="cyan"))
        click.echo(click.style("  CHAKRAVYUH LEAK SUITE — Covert Channel Probes", fg="cyan", bold=True))
        click.echo(click.style("═" * 60, fg="cyan"))
        click.echo(f"  Running {total} probe(s)...\n")

        for i, probe in enumerate(probes, 1):
            click.echo(
                click.style(f"  [{i}/{total}] ", fg="white", bold=True)
                + click.style(f"{probe.name}", fg="cyan")
                + f" — {probe.description}"
            )

            probe_start = time.monotonic()

            try:
                result = probe.run()
            except Exception as exc:
                result = ProbeResult(
                    probe_name=probe.name,
                    passed=False,
                    measured_value=-1.0,
                    unit="error",
                    threshold=probe.pass_threshold,
                    details=f"Unhandled exception: {exc}",
                )

            probe_elapsed = time.monotonic() - probe_start
            self.results.append(result)

            # Print result
            status = (
                click.style("  ✅ PASS", fg="green", bold=True)
                if result.passed
                else click.style("  ❌ FAIL", fg="red", bold=True)
            )
            click.echo(
                f"  {status}  "
                f"measured={result.measured_value} {result.unit}  "
                f"threshold={result.threshold}  "
                f"({probe_elapsed:.2f}s)"
            )

            if self.verbose and result.details:
                for line in result.details.split("\n"):
                    click.echo(click.style(f"         {line}", fg="white", dim=True))

            click.echo()

        self._end_time = time.monotonic()

        # --- Summary ---
        self._print_summary()

        return self.results

    def _print_summary(self) -> None:
        """Print a summary table of all probe results."""
        elapsed = (
            (self._end_time - self._start_time)
            if self._start_time and self._end_time
            else 0.0
        )

        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        all_passed = passed == total

        click.echo(click.style("═" * 60, fg="cyan"))
        click.echo(click.style("  SUMMARY", fg="cyan", bold=True))
        click.echo(click.style("═" * 60, fg="cyan"))

        # Build table
        table_data = []
        for r in self.results:
            status = "✅ PASS" if r.passed else "❌ FAIL"
            table_data.append([
                r.probe_name,
                f"{r.measured_value:.4f}" if r.measured_value >= 0 else "ERROR",
                r.unit,
                f"{r.threshold}",
                status,
            ])

        headers = ["Probe", "Measured", "Unit", "Threshold", "Status"]
        click.echo(tabulate(table_data, headers=headers, tablefmt="grid"))
        click.echo()

        summary_color = "green" if all_passed else "red"
        click.echo(
            click.style(
                f"  Result: {passed}/{total} probes passed  |  "
                f"Total time: {elapsed:.2f}s",
                fg=summary_color,
                bold=True,
            )
        )

        if all_passed:
            click.echo(click.style(
                "  🛡️  All covert-channel probes within budget. Isolation verified.",
                fg="green",
            ))
        else:
            click.echo(click.style(
                "  ⚠️  Some probes exceeded the leak budget. Review findings above.",
                fg="red",
            ))

        click.echo()

    def get_results_dict(self) -> dict:
        """
        Return all results as a serialisable dictionary.

        Useful for JSON export and report generation.
        """
        return {
            "suite": "CHAKRAVYUH Leak Suite",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_probes": len(self.results),
            "passed": sum(1 for r in self.results if r.passed),
            "failed": sum(1 for r in self.results if not r.passed),
            "all_passed": all(r.passed for r in self.results),
            "elapsed_seconds": (
                round(self._end_time - self._start_time, 3)
                if self._start_time and self._end_time
                else None
            ),
            "results": [
                {
                    "probe_name": r.probe_name,
                    "passed": r.passed,
                    "measured_value": r.measured_value,
                    "unit": r.unit,
                    "threshold": r.threshold,
                    "details": r.details,
                    "timestamp": r.timestamp,
                    "raw_data": r.raw_data,
                }
                for r in self.results
            ],
        }


# ═══════════════════════════════════════════════════════════════════════
# CLI Interface (Click)
# ═══════════════════════════════════════════════════════════════════════

@click.command()
@click.option(
    "--probe", "-p",
    multiple=True,
    default=["all"],
    help=(
        "Probe(s) to run. Use 'all' for the full suite, or specify "
        "individual probes: cpu_timing, procfs, network_scan, "
        "kv_cache_canary, cache_contention."
    ),
)
@click.option(
    "--report", "-r",
    is_flag=True,
    default=False,
    help="Generate a markdown report after running probes.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Path for the JSON results file (default: results/results.json).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Print detailed output for each probe.",
)
def main(probe: tuple, report: bool, output: Optional[str], verbose: bool) -> None:
    """
    CHAKRAVYUH Leak Suite — Covert Channel Probe Runner.

    Runs covert-channel probes against the triple-plane sandbox to verify
    that information leakage is within the acceptable budget.

    \b
    Examples:
        python runner.py --probe all
        python runner.py --probe cpu_timing --probe procfs --verbose
        python runner.py --probe all --report
    """
    runner = ProbeRunner(verbose=verbose)

    # Discover and load probes
    try:
        probes = runner.discover_probes(list(probe))
    except ValueError as exc:
        click.echo(click.style(f"Error: {exc}", fg="red"), err=True)
        sys.exit(2)

    if not probes:
        click.echo(click.style("No probes to run.", fg="yellow"))
        sys.exit(0)

    # Run probes
    results = runner.run_probes(probes)

    # Save JSON results
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    json_path = Path(output) if output else results_dir / "results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(runner.get_results_dict(), f, indent=2, default=str)
    click.echo(f"  📄 Results saved to: {json_path}")

    # Generate report if requested
    if report:
        from report import ReportGenerator

        report_gen = ReportGenerator()
        report_path = report_gen.generate(runner.get_results_dict())
        click.echo(f"  📝 Report saved to: {report_path}")

    # Exit with non-zero if any probe failed
    all_passed = all(r.passed for r in results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()

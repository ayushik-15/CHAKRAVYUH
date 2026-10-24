"""
CHAKRAVYUH Leak Suite — Report Generator
==========================================

Generates a formatted Markdown report from probe results, including:
    - Header with project metadata and timestamp.
    - Summary table of all probe results with pass/fail status.
    - Detailed per-probe analysis sections.
    - Aggregate statistics and leak budget assessment.

The report is written to `leak-suite/results/report.md` by default.

Usage:
    # Typically called from runner.py:
    python runner.py --probe all --report

    # Can also be used standalone:
    from report import ReportGenerator
    gen = ReportGenerator()
    gen.generate(results_dict)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class ReportGenerator:
    """
    Generates a formatted Markdown report from Leak Suite probe results.

    The report is designed to be:
        1. Human-readable for hackathon judges and security auditors.
        2. Machine-parseable (structured tables, consistent formatting).
        3. Self-contained — includes all context needed to interpret results.

    Attributes:
        output_dir: Directory where the report file is written.
    """

    def __init__(self, output_dir: Optional[str] = None) -> None:
        """
        Initialise the report generator.

        Args:
            output_dir: Path to the output directory. Defaults to
                        `leak-suite/results/`.
        """
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent / "results"

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: Dict[str, Any]) -> Path:
        """
        Generate a Markdown report from the probe results dictionary.

        Args:
            results: Dictionary from ProbeRunner.get_results_dict(), containing
                     suite metadata and a list of ProbeResult-like dicts.

        Returns:
            Path to the generated report file.
        """
        report_lines: list[str] = []

        # ── Header ──
        report_lines.extend(self._build_header(results))

        # ── Executive Summary ──
        report_lines.extend(self._build_executive_summary(results))

        # ── Results Table ──
        report_lines.extend(self._build_results_table(results))

        # ── Detailed Probe Analysis ──
        report_lines.extend(self._build_detailed_analysis(results))

        # ── Aggregate Statistics ──
        report_lines.extend(self._build_aggregate_stats(results))

        # ── Leak Budget Assessment ──
        report_lines.extend(self._build_leak_budget(results))

        # ── Footer ──
        report_lines.extend(self._build_footer())

        # Write report
        report_path = self.output_dir / "report.md"
        report_content = "\n".join(report_lines)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        return report_path

    # ═══════════════════════════════════════════════════════════════════
    # Report Sections
    # ═══════════════════════════════════════════════════════════════════

    @staticmethod
    def _build_header(results: Dict[str, Any]) -> list[str]:
        """Build the report header with project metadata."""
        timestamp = results.get("timestamp", datetime.now(timezone.utc).isoformat())
        return [
            "# 🛡️ CHAKRAVYUH Leak Suite — Covert Channel Audit Report",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Project** | CHAKRAVYUH — Secure Adversarial AI Safety Testing |",
            f"| **Component** | Leak Suite (Phase 7) |",
            f"| **Timestamp** | {timestamp} |",
            f"| **Total Probes** | {results.get('total_probes', 0)} |",
            f"| **Passed** | {results.get('passed', 0)} |",
            f"| **Failed** | {results.get('failed', 0)} |",
            f"| **Execution Time** | {results.get('elapsed_seconds', 'N/A')}s |",
            "",
            "---",
            "",
        ]

    @staticmethod
    def _build_executive_summary(results: Dict[str, Any]) -> list[str]:
        """Build the executive summary section."""
        all_passed = results.get("all_passed", False)
        passed = results.get("passed", 0)
        total = results.get("total_probes", 0)

        if all_passed:
            verdict = (
                "✅ **ALL PROBES PASSED** — The triple-plane sandbox demonstrates "
                "adequate isolation. All measured covert-channel capacities are within "
                "the acceptable leak budget."
            )
        else:
            failed = results.get("failed", 0)
            verdict = (
                f"❌ **{failed} PROBE(S) FAILED** — The sandbox isolation has gaps. "
                f"Review the detailed findings below and apply the recommended "
                f"mitigations before deploying to production."
            )

        return [
            "## Executive Summary",
            "",
            verdict,
            "",
            f"**Overall Score: {passed}/{total}**",
            "",
            "---",
            "",
        ]

    @staticmethod
    def _build_results_table(results: Dict[str, Any]) -> list[str]:
        """Build the main results summary table."""
        lines = [
            "## Probe Results",
            "",
            "| # | Probe | Measured | Unit | Threshold | Status |",
            "|---|-------|----------|------|-----------|--------|",
        ]

        for i, probe in enumerate(results.get("results", []), 1):
            measured = probe.get("measured_value", -1)
            measured_str = f"{measured:.4f}" if measured >= 0 else "ERROR"
            status = "✅ PASS" if probe.get("passed", False) else "❌ FAIL"

            lines.append(
                f"| {i} | **{probe.get('probe_name', 'unknown')}** | "
                f"{measured_str} | {probe.get('unit', '')} | "
                f"{probe.get('threshold', '')} | {status} |"
            )

        lines.extend(["", "---", ""])
        return lines

    @staticmethod
    def _build_detailed_analysis(results: Dict[str, Any]) -> list[str]:
        """Build detailed per-probe analysis sections."""
        lines = ["## Detailed Probe Analysis", ""]

        for probe in results.get("results", []):
            name = probe.get("probe_name", "unknown")
            passed = probe.get("passed", False)
            status_emoji = "✅" if passed else "❌"

            lines.append(f"### {status_emoji} {name}")
            lines.append("")

            # Details block
            details = probe.get("details", "No details available.")
            lines.append("```")
            lines.append(details)
            lines.append("```")
            lines.append("")

            # Raw data (if available)
            raw_data = probe.get("raw_data")
            if raw_data:
                lines.append("<details>")
                lines.append("<summary>Raw Data</summary>")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(raw_data, indent=2, default=str))
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            lines.append("---")
            lines.append("")

        return lines

    @staticmethod
    def _build_aggregate_stats(results: Dict[str, Any]) -> list[str]:
        """Build aggregate statistics section."""
        probe_results = results.get("results", [])

        if not probe_results:
            return ["## Aggregate Statistics", "", "No probe results available.", "", "---", ""]

        # Collect timing channel results
        timing_probes = [
            p for p in probe_results
            if p.get("unit") == "bits/sec" and p.get("measured_value", -1) >= 0
        ]

        # Collect logical channel results
        logical_probes = [
            p for p in probe_results
            if p.get("unit") == "count" and p.get("measured_value", -1) >= 0
        ]

        lines = [
            "## Aggregate Statistics",
            "",
            "### Timing Channels (bits/sec)",
            "",
        ]

        if timing_probes:
            values = [p["measured_value"] for p in timing_probes]
            lines.extend([
                f"- **Max leakage:** {max(values):.6f} bits/sec",
                f"- **Mean leakage:** {sum(values) / len(values):.6f} bits/sec",
                f"- **Probes tested:** {len(timing_probes)}",
                "",
            ])
        else:
            lines.extend(["- No timing channel probes completed.", ""])

        lines.extend([
            "### Logical Channels (count)",
            "",
        ])

        if logical_probes:
            values = [p["measured_value"] for p in logical_probes]
            lines.extend([
                f"- **Total leaks detected:** {int(sum(values))}",
                f"- **Probes tested:** {len(logical_probes)}",
                "",
            ])
        else:
            lines.extend(["- No logical channel probes completed.", ""])

        lines.extend(["---", ""])
        return lines

    @staticmethod
    def _build_leak_budget(results: Dict[str, Any]) -> list[str]:
        """Build the leak budget assessment section."""
        lines = [
            "## Leak Budget Assessment",
            "",
            "CHAKRAVYUH defines the following leak budget thresholds:",
            "",
            "| Channel Type | Budget | Rationale |",
            "|-------------|--------|-----------|",
            "| Timing (CPU) | ≤ 0.5 bits/sec | Below practical exploitation threshold |",
            "| Timing (Cache) | ≤ 0.5 bits/sec | Below practical exploitation threshold |",
            "| Logical (/proc) | 0 leaks | Any procfs leakage is a namespace violation |",
            "| Logical (Network) | 0 responses | Any cross-plane response is a segmentation failure |",
            "| Logical (KV-Cache) | 0 reuses | Any canary reuse is a cache isolation failure |",
            "",
        ]

        all_passed = results.get("all_passed", False)
        if all_passed:
            lines.extend([
                "> ✅ **All measured values are within the defined leak budget.**",
                "> The CHAKRAVYUH sandbox meets the isolation requirements for",
                "> adversarial AI safety testing under EU AI Act and NIST AI RMF guidelines.",
            ])
        else:
            lines.extend([
                "> ❌ **Some probes exceeded the leak budget.**",
                "> Review the failed probes above and apply mitigations before",
                "> using this sandbox for regulated safety evaluations.",
            ])

        lines.extend(["", "---", ""])
        return lines

    @staticmethod
    def _build_footer() -> list[str]:
        """Build the report footer."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return [
            "## Methodology",
            "",
            "This report was generated by the CHAKRAVYUH Leak Suite, which implements",
            "5 covert-channel probes targeting the triple-plane sandbox architecture:",
            "",
            "1. **CPU Timing** — Measures rdtsc-based timing jitter to estimate the",
            "   capacity of a modulated timing covert channel.",
            "2. **Procfs Snooping** — Attempts to read /proc entries of other containers",
            "   to verify PID namespace and procfs virtualisation.",
            "3. **Network Scan** — Scans ports and DNS to verify network segmentation.",
            "4. **KV-Cache Canary** — Injects canary strings into LLM sessions to detect",
            "   cross-session state leakage via KV-cache reuse.",
            "5. **Cache Contention** — Measures L3 cache timing variations to estimate",
            "   the mutual information between workload activity and cache access times.",
            "",
            "---",
            "",
            f"*Generated by CHAKRAVYUH Leak Suite at {timestamp}*",
            f"*Project CHAKRAVYUH — Team Vision Grid — Hack in Hills '26*",
            "",
        ]

"""
CHAKRAVYUH Leak Suite — /proc Filesystem Snooping Probe
========================================================

Probe: ProcfsProbe
Covert Channel Class: Logical information leakage via shared /proc filesystem

What This Tests:
    The Linux /proc pseudo-filesystem exposes a wealth of process and system
    information. In a poorly isolated container environment, a process in one
    plane might be able to read /proc entries belonging to processes in other
    planes — revealing PIDs, memory maps, network connections, and more.

    This probe attempts to read:
        1. /proc/<pid> entries of processes outside this container's PID
           namespace (should fail if PID namespaces are correctly configured).
        2. /proc/net/tcp — TCP connection table (could reveal other planes'
           connections to the Arbiter).
        3. /proc/meminfo — System-wide memory information (could reveal
           aggregate activity of other planes).
        4. /proc/loadavg — System load average (could reveal activity patterns).
        5. Host-level /proc entries that should be masked by the container
           runtime.

Why It Matters:
    - /proc leakage is one of the most common container escape vectors.
    - Even read-only access to /proc/net/tcp reveals listening ports and
      active connections of co-tenants.
    - gVisor and Firecracker mitigate this by virtualising /proc, but
      default Docker does NOT.

Pass Condition:
    ALL cross-plane reads must fail with PermissionError or FileNotFoundError.
    Measured value is the count of successful cross-plane reads (must be 0).

Methodology:
    1. Enumerate PIDs visible in /proc/ (outside our own PID namespace).
    2. Attempt to read /proc/<pid>/cmdline, /proc/<pid>/status for each.
    3. Read /proc/net/tcp and check for connections to other plane IPs.
    4. Read /proc/meminfo and /proc/loadavg for information content.
    5. Count successful cross-boundary reads.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

from . import BaseProbe, ProbeResult


class ProcfsProbe(BaseProbe):
    """
    Attempts to read /proc entries belonging to other containers/planes.

    A passing result means the container's /proc is properly namespaced
    and virtualised — no cross-plane information is accessible.
    """

    name: str = "procfs_snoop"
    description: str = (
        "Checks whether /proc filesystem entries from other containers "
        "are visible, testing PID namespace and procfs isolation."
    )
    pass_threshold: float = 0.0  # Zero successful cross-plane reads

    # Known plane hostnames/IPs to look for in /proc/net/tcp
    OTHER_PLANE_IDENTIFIERS: List[str] = [
        "red-plane", "blue-plane", "llm-plane",
        "chakravyuh-red-plane", "chakravyuh-blue-plane", "chakravyuh-llm-plane",
    ]

    # Sensitive /proc paths that should be restricted
    SENSITIVE_PROC_PATHS: List[str] = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
        "/proc/meminfo",
        "/proc/loadavg",
        "/proc/stat",
        "/proc/diskstats",
        "/proc/interrupts",
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/sched_debug",
    ]

    def run(self) -> ProbeResult:
        """
        Execute the procfs snooping probe.

        Attempts to read various /proc entries that could leak information
        about other containers. Counts the number of successful reads that
        reveal cross-plane information.

        Returns:
            ProbeResult with the count of successful cross-plane reads.
        """
        try:
            findings: List[str] = []
            successful_reads = 0

            # --- Test 1: Foreign PID enumeration ---
            foreign_pid_count, pid_details = self._check_foreign_pids()
            if foreign_pid_count > 0:
                successful_reads += foreign_pid_count
                findings.append(
                    f"[FAIL] Found {foreign_pid_count} foreign PID(s) readable: {pid_details}"
                )
            else:
                findings.append("[PASS] No foreign PIDs readable outside container namespace")

            # --- Test 2: Cross-plane network connections ---
            cross_plane_conns, conn_details = self._check_network_connections()
            if cross_plane_conns > 0:
                successful_reads += cross_plane_conns
                findings.append(
                    f"[FAIL] Found {cross_plane_conns} cross-plane connection(s) visible: {conn_details}"
                )
            else:
                findings.append("[PASS] No cross-plane network connections visible in /proc/net/tcp")

            # --- Test 3: Sensitive /proc file access ---
            sensitive_access, sensitive_details = self._check_sensitive_paths()
            if sensitive_access > 0:
                # Not all sensitive reads are failures — /proc/meminfo is often
                # available but with limited information. We flag only those that
                # contain identifiable cross-plane data.
                findings.append(
                    f"[INFO] {sensitive_access} sensitive /proc path(s) readable: {sensitive_details}"
                )
                # Only count as leaks if they contain cross-plane identifiers
                cross_plane_leaks = self._scan_for_cross_plane_data(sensitive_details)
                successful_reads += cross_plane_leaks
                if cross_plane_leaks > 0:
                    findings.append(
                        f"[FAIL] {cross_plane_leaks} sensitive path(s) contain cross-plane data"
                    )
            else:
                findings.append("[PASS] All sensitive /proc paths are restricted")

            # --- Test 4: /proc/1 access (host init process) ---
            host_init_accessible = self._check_host_init()
            if host_init_accessible:
                successful_reads += 1
                findings.append("[FAIL] /proc/1 appears to be the HOST init (not container init)")
            else:
                findings.append("[PASS] /proc/1 is correctly namespaced to container init")

            passed = successful_reads <= self.pass_threshold

            details = (
                f"Procfs Snooping Analysis\n"
                f"  Successful cross-plane reads: {successful_reads}\n"
                f"  Threshold:                    {int(self.pass_threshold)} (must be 0)\n"
                f"  Result:                       {'PASS ✅' if passed else 'FAIL ❌'}\n"
                f"\n  Detailed Findings:\n"
                + "\n".join(f"    {f}" for f in findings)
            )

            return ProbeResult(
                probe_name=self.name,
                passed=passed,
                measured_value=float(successful_reads),
                unit="count",
                threshold=self.pass_threshold,
                details=details,
                raw_data={
                    "foreign_pids": foreign_pid_count,
                    "cross_plane_connections": cross_plane_conns,
                    "sensitive_paths_accessible": sensitive_access,
                    "host_init_accessible": host_init_accessible,
                    "total_leaks": successful_reads,
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

    def _check_foreign_pids(self) -> Tuple[int, str]:
        """
        Enumerate PIDs in /proc/ and attempt to read their cmdline.

        In a properly namespaced container, we should only see our own
        processes. Any PID whose cmdline references another plane's
        binary (e.g., 'attacker.py', 'defender.py') is a foreign PID.
        """
        foreign_pids: List[str] = []
        own_pid = os.getpid()

        proc_path = Path("/proc")
        if not proc_path.exists():
            return 0, "(/proc not available — likely Windows/non-Linux environment)"

        for entry in proc_path.iterdir():
            if not entry.name.isdigit():
                continue

            pid = int(entry.name)
            if pid == own_pid or pid == 1:
                continue  # Skip self and container init

            try:
                cmdline = (entry / "cmdline").read_text(errors="replace")
                # Check if this PID belongs to another plane
                for identifier in self.OTHER_PLANE_IDENTIFIERS:
                    if identifier in cmdline:
                        foreign_pids.append(f"PID {pid}: {cmdline[:80]}")
                        break
            except (PermissionError, FileNotFoundError, OSError):
                # Expected: permission denied or not found = good isolation
                pass

        return len(foreign_pids), "; ".join(foreign_pids) if foreign_pids else "(none)"

    def _check_network_connections(self) -> Tuple[int, str]:
        """
        Read /proc/net/tcp and check for connections to other plane IPs.

        In an isolated container, /proc/net/tcp should only show connections
        within this plane's network namespace. Connections to other planes'
        IPs indicate broken network namespace isolation.
        """
        cross_plane: List[str] = []

        tcp_path = Path("/proc/net/tcp")
        if not tcp_path.exists():
            return 0, "(/proc/net/tcp not available)"

        try:
            content = tcp_path.read_text(errors="replace")
            # Parse /proc/net/tcp: each line has local_addr:port rem_addr:port
            for line in content.strip().split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 3:
                    continue
                remote_addr = parts[2]
                # Decode hex IP
                try:
                    ip_hex, port_hex = remote_addr.split(":")
                    ip_int = int(ip_hex, 16)
                    ip_str = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                    port = int(port_hex, 16)
                    # We flag any non-loopback, non-zero connection for analysis
                    if not ip_str.startswith("127.") and ip_str != "0.0.0.0" and port != 0:
                        cross_plane.append(f"{ip_str}:{port}")
                except (ValueError, IndexError):
                    continue

        except (PermissionError, FileNotFoundError, OSError):
            return 0, "(access denied — good)"

        return len(cross_plane), "; ".join(cross_plane) if cross_plane else "(none)"

    def _check_sensitive_paths(self) -> Tuple[int, Dict[str, str]]:
        """
        Attempt to read sensitive /proc paths and record which are accessible.
        """
        accessible: Dict[str, str] = {}

        for proc_path in self.SENSITIVE_PROC_PATHS:
            path = Path(proc_path)
            try:
                content = path.read_text(errors="replace")[:200]  # First 200 chars
                accessible[proc_path] = content
            except (PermissionError, FileNotFoundError, OSError):
                pass  # Expected: restricted access

        return len(accessible), accessible

    def _scan_for_cross_plane_data(self, path_contents: Dict[str, str]) -> int:
        """
        Scan readable /proc contents for identifiers from other planes.

        Returns the count of paths that contain cross-plane data.
        """
        leaks = 0
        for path, content in path_contents.items():
            for identifier in self.OTHER_PLANE_IDENTIFIERS:
                if identifier in content:
                    leaks += 1
                    break
        return leaks

    def _check_host_init(self) -> bool:
        """
        Check if /proc/1 is the host's init process or the container's.

        In a properly namespaced container, PID 1 is the container's
        entrypoint process. If /proc/1/cmdline contains 'systemd' or 'init',
        we might be seeing the host's init — a namespace leak.
        """
        try:
            cmdline = Path("/proc/1/cmdline").read_text(errors="replace")
            # Host init indicators
            host_indicators = ["systemd", "/sbin/init", "launchd"]
            return any(indicator in cmdline for indicator in host_indicators)
        except (PermissionError, FileNotFoundError, OSError):
            return False  # Can't read = likely isolated

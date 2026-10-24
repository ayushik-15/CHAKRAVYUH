"""
CHAKRAVYUH Leak Suite — Network Scan Probe
============================================

Probe: NetworkScanProbe
Covert Channel Class: Network-layer cross-plane discovery and communication

What This Tests:
    In the CHAKRAVYUH architecture, each plane (Red, Blue, LLM) is placed on
    a separate Docker bridge network. The only entity reachable from any plane
    is the Arbiter — direct plane-to-plane communication is forbidden.

    This probe verifies network isolation by:
        1. Attempting TCP connections to common ports on other planes' IPs
           and hostnames.
        2. Trying DNS resolution of other plane hostnames (if DNS leaks
           across networks, an attacker can discover other planes' IPs).
        3. Scanning a range of ports that other services might listen on.

    Any successful connection or resolution means the network isolation is
    broken, and a covert channel could be established.

Why It Matters:
    - Network isolation is the *first line of defence* in the triple-plane
      sandbox. If it fails, all higher-level protections (CREP, KV-cache
      firewall) are moot.
    - Docker's default bridge networking does NOT prevent cross-container
      communication — explicit network segmentation is required.
    - DNS is often overlooked: if plane A can resolve plane B's hostname,
      it can discover plane B's IP even without direct connectivity.

Pass Condition:
    Zero successful connections or DNS resolutions to other planes.
    Measured value is the total count of successful responses (must be 0).
"""

from __future__ import annotations

import socket
from typing import Dict, List, Tuple

from . import BaseProbe, ProbeResult


class NetworkScanProbe(BaseProbe):
    """
    Scans for network-layer visibility of other planes.

    Attempts TCP connections and DNS lookups targeting other planes'
    hostnames and common ports. In a properly isolated environment,
    all attempts must fail.
    """

    name: str = "network_scan"
    description: str = (
        "Scans common ports on other plane IPs and attempts DNS resolution "
        "of other plane hostnames to verify network isolation."
    )
    pass_threshold: float = 0.0  # Zero successful responses

    # Hostnames of other planes (from docker-compose.yml)
    OTHER_PLANE_HOSTNAMES: List[str] = [
        "red-plane",
        "blue-plane",
        "llm-plane",
        "chakravyuh-red-plane",
        "chakravyuh-blue-plane",
        "chakravyuh-llm-plane",
    ]

    # Common ports that services might listen on
    SCAN_PORTS: List[int] = [
        22,    # SSH
        80,    # HTTP
        443,   # HTTPS
        3000,  # Frontend (Next.js)
        5432,  # PostgreSQL
        8000,  # Arbiter
        8001,  # Merkle Log
        8080,  # Common HTTP alt
        8443,  # Common HTTPS alt
        6379,  # Redis
        27017, # MongoDB
        9090,  # Prometheus
    ]

    # Connection timeout in seconds (keep short — we just need to detect
    # reachability, not establish a full session)
    CONNECT_TIMEOUT_S: float = 2.0

    def run(self) -> ProbeResult:
        """
        Execute the network scan probe.

        Performs DNS resolution attempts and TCP connection attempts to
        all other plane hostnames on common ports. Counts any successful
        response as a failure.

        Returns:
            ProbeResult with the count of successful cross-plane responses.
        """
        try:
            findings: List[str] = []
            total_successful = 0

            # --- Test 1: DNS resolution of other plane hostnames ---
            dns_successes, dns_details = self._dns_scan()
            total_successful += dns_successes
            if dns_successes > 0:
                findings.append(
                    f"[FAIL] DNS resolved {dns_successes} other plane hostname(s):"
                )
                for hostname, ip in dns_details.items():
                    findings.append(f"       {hostname} → {ip}")
            else:
                findings.append("[PASS] No other plane hostnames resolved via DNS")

            # --- Test 2: TCP port scan on resolved IPs and hostnames ---
            port_successes, port_details = self._port_scan(dns_details)
            total_successful += port_successes
            if port_successes > 0:
                findings.append(
                    f"[FAIL] TCP connected to {port_successes} port(s) on other planes:"
                )
                for target, ports in port_details.items():
                    findings.append(f"       {target} — open ports: {ports}")
            else:
                findings.append("[PASS] No TCP connections succeeded to other planes")

            # --- Test 3: Reverse DNS / ARP scan for subnet neighbours ---
            neighbour_count, neighbour_details = self._subnet_scan()
            total_successful += neighbour_count
            if neighbour_count > 0:
                findings.append(
                    f"[FAIL] Discovered {neighbour_count} neighbour(s) on local subnet:"
                )
                for detail in neighbour_details:
                    findings.append(f"       {detail}")
            else:
                findings.append("[PASS] No unexpected neighbours discovered on subnet")

            passed = total_successful <= self.pass_threshold

            details = (
                f"Network Scan Analysis\n"
                f"  DNS resolutions:    {dns_successes}\n"
                f"  Open ports:         {port_successes}\n"
                f"  Subnet neighbours:  {neighbour_count}\n"
                f"  Total responses:    {total_successful}\n"
                f"  Threshold:          {int(self.pass_threshold)} (must be 0)\n"
                f"  Result:             {'PASS ✅' if passed else 'FAIL ❌'}\n"
                f"\n  Detailed Findings:\n"
                + "\n".join(f"    {f}" for f in findings)
            )

            return ProbeResult(
                probe_name=self.name,
                passed=passed,
                measured_value=float(total_successful),
                unit="count",
                threshold=self.pass_threshold,
                details=details,
                raw_data={
                    "dns_successes": dns_successes,
                    "dns_resolved": dns_details,
                    "port_successes": port_successes,
                    "open_ports": port_details,
                    "subnet_neighbours": neighbour_count,
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

    def _dns_scan(self) -> Tuple[int, Dict[str, str]]:
        """
        Attempt DNS resolution of all other plane hostnames.

        In a properly segmented Docker network, DNS should only resolve
        hostnames within the same network. Cross-network hostname
        resolution indicates a DNS configuration leak.

        Returns:
            (count of successful resolutions, dict of hostname→IP)
        """
        resolved: Dict[str, str] = {}

        for hostname in self.OTHER_PLANE_HOSTNAMES:
            try:
                ip = socket.gethostbyname(hostname)
                resolved[hostname] = ip
            except (socket.gaierror, socket.herror, OSError):
                # Expected: hostname not found = good isolation
                pass

        return len(resolved), resolved

    def _port_scan(self, resolved_hosts: Dict[str, str]) -> Tuple[int, Dict[str, List[int]]]:
        """
        Attempt TCP connections to common ports on other planes.

        Scans both resolved IPs (from DNS) and raw hostnames. Uses a
        short timeout to avoid blocking on unreachable hosts.

        Returns:
            (count of open ports, dict of target→list of open ports)
        """
        open_ports: Dict[str, List[int]] = {}

        # Build target list: resolved IPs + hostnames
        targets = set(self.OTHER_PLANE_HOSTNAMES)
        targets.update(resolved_hosts.values())

        for target in targets:
            target_open: List[int] = []
            for port in self.SCAN_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.CONNECT_TIMEOUT_S)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    if result == 0:
                        target_open.append(port)
                except (socket.error, OSError):
                    pass

            if target_open:
                open_ports[target] = target_open

        total = sum(len(ports) for ports in open_ports.values())
        return total, open_ports

    def _subnet_scan(self) -> Tuple[int, List[str]]:
        """
        Attempt to discover neighbours on the local subnet.

        Gets the container's own IP and scans nearby addresses on the
        /24 subnet. In an isolated network, only the gateway (Docker
        bridge) and possibly the Arbiter should respond.

        Returns:
            (count of unexpected neighbours, list of details)
        """
        neighbours: List[str] = []

        try:
            # Get own IP
            own_ip = self._get_own_ip()
            if not own_ip or own_ip == "127.0.0.1":
                return 0, ["(could not determine own IP)"]

            # Parse subnet (assume /24)
            octets = own_ip.split(".")
            if len(octets) != 4:
                return 0, ["(invalid IP format)"]

            subnet_prefix = ".".join(octets[:3])

            # Scan a few IPs around ours (skip broadcast and network addresses)
            for last_octet in range(1, 20):
                target_ip = f"{subnet_prefix}.{last_octet}"
                if target_ip == own_ip:
                    continue

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    # Try a common port
                    result = sock.connect_ex((target_ip, 8080))
                    sock.close()
                    if result == 0:
                        neighbours.append(f"{target_ip}:8080 (open)")
                except (socket.error, OSError):
                    pass

        except Exception:
            pass

        return len(neighbours), neighbours

    @staticmethod
    def _get_own_ip() -> str:
        """Get the container's primary IP address."""
        try:
            # Connect to a dummy address to find our outgoing IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.connect(("10.255.255.255", 1))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except (socket.error, OSError):
            return "127.0.0.1"

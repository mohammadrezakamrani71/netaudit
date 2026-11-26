"""Network diagnostics module: DNS, TCP port reachability, TLS inspection, and CIDR analysis."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    name: str
    target: str
    status: str  # "PASS", "WARN", "FAIL"
    detail: str
    latency_ms: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def check_dns(hostname: str, timeout: float = 3.0) -> CheckResult:
    """Resolve a hostname to IPv4/IPv6 addresses and measure lookup latency."""
    start = time.perf_counter()
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        ips = sorted({info[4][0] for info in infos})
        return CheckResult(
            name="DNS Resolution",
            target=hostname,
            status="PASS",
            detail=f"Resolved to {', '.join(ips)}",
            latency_ms=elapsed_ms,
            metadata={"ips": ips},
        )
    except socket.gaierror as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return CheckResult(
            name="DNS Resolution",
            target=hostname,
            status="FAIL",
            detail=f"DNS resolution failed: {exc}",
            latency_ms=elapsed_ms,
        )
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> CheckResult:
    """Test TCP port reachability and measure connection latency."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return CheckResult(
                name=f"TCP Port {port}",
                target=f"{host}:{port}",
                status="PASS",
                detail=f"Port {port} is open and reachable",
                latency_ms=elapsed_ms,
            )
    except (OSError, TimeoutError) as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return CheckResult(
            name=f"TCP Port {port}",
            target=f"{host}:{port}",
            status="FAIL",
            detail=f"Connection failed: {exc}",
            latency_ms=elapsed_ms,
        )


def check_tls_certificate(host: str, port: int = 443, timeout: float = 4.0) -> CheckResult:
    """Inspect TLS protocol version and certificate expiration."""
    ctx = ssl.create_default_context()
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                cert = ssock.getpeercert()
                tls_version = ssock.version() or "Unknown"
                not_after_raw = cert.get("notAfter", "") if cert else ""
                if not_after_raw:
                    expires_at = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_left = (expires_at - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        status = "FAIL"
                        detail = f"Certificate EXPIRED ({abs(days_left)} days ago) | {tls_version}"
                    elif days_left <= 30:
                        status = "WARN"
                        detail = f"Certificate expires soon ({days_left} days left) | {tls_version}"
                    else:
                        status = "PASS"
                        detail = f"Valid ({days_left} days remaining) | {tls_version}"
                else:
                    status = "WARN"
                    detail = f"Certificate retrieved without expiry metadata | {tls_version}"
                return CheckResult(
                    name="TLS Certificate",
                    target=f"{host}:{port}",
                    status=status,
                    detail=detail,
                    latency_ms=elapsed_ms,
                    metadata={"tls_version": tls_version},
                )
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return CheckResult(
            name="TLS Certificate",
            target=f"{host}:{port}",
            status="FAIL",
            detail=f"TLS inspection failed: {exc}",
            latency_ms=elapsed_ms,
        )


def analyze_subnets(cidrs: list[str]) -> list[CheckResult]:
    """Validate CIDR subnets and detect overlapping address spaces."""
    results: list[CheckResult] = []
    parsed: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []

    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            parsed.append((cidr, net))
            usable = max(net.num_addresses - 2, 0) if net.version == 4 and net.prefixlen < 31 else net.num_addresses
            scope = "Private" if net.is_private else "Public"
            results.append(
                CheckResult(
                    name="Subnet Validation",
                    target=str(net),
                    status="PASS",
                    detail=f"Valid IPv{net.version} {scope} network | Usable hosts: {usable}",
                    metadata={"network": str(net), "usable_hosts": usable, "is_private": net.is_private},
                )
            )
        except ValueError as exc:
            results.append(
                CheckResult(
                    name="Subnet Validation",
                    target=cidr,
                    status="FAIL",
                    detail=f"Invalid CIDR notation: {exc}",
                )
            )

    for i in range(len(parsed)):
        for j in range(i + 1, len(parsed)):
            cidr_a, net_a = parsed[i]
            cidr_b, net_b = parsed[j]
            if net_a.version == net_b.version and net_a.overlaps(net_b):
                results.append(
                    CheckResult(
                        name="Subnet Overlap Check",
                        target=f"{cidr_a} <-> {cidr_b}",
                        status="FAIL",
                        detail=f"Overlapping address space detected between {net_a} and {net_b}",
                    )
                )

    return results

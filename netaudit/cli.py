"""Command-line interface for NetAudit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diagnostics import CheckResult, analyze_subnets, check_dns, check_tcp_port, check_tls_certificate
from .hardening import HardeningFinding, audit_cisco_config
from .reporter import render_html_report, render_markdown_report


def run_diagnostics_from_file(targets_path: Path) -> list[CheckResult]:
    data = json.loads(targets_path.read_text(encoding="utf-8"))
    results: list[CheckResult] = []

    for host in data.get("dns", []):
        results.append(check_dns(host))

    for item in data.get("tcp", []):
        results.append(check_tcp_port(item["host"], int(item["port"])))

    for item in data.get("tls", []):
        results.append(check_tls_certificate(item["host"], int(item.get("port", 443))))

    if data.get("subnets"):
        results.extend(analyze_subnets(data["subnets"]))

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="Automated Network Diagnostics & Cisco IOS Hardening Auditor",
    )
    parser.add_argument("--targets", type=Path, help="Path to JSON file with dns/tcp/tls/subnets targets")
    parser.add_argument("--config", type=Path, help="Path to Cisco IOS running-config file to audit")
    parser.add_argument("--out-md", type=Path, help="Optional output path for Markdown report")
    parser.add_argument("--out-html", type=Path, help="Optional output path for HTML report")
    args = parser.parse_args(argv)

    if not args.targets and not args.config:
        parser.error("Provide at least one of --targets or --config.")

    diag_results: list[CheckResult] = []
    hardening_results: list[HardeningFinding] = []

    if args.targets:
        diag_results = run_diagnostics_from_file(args.targets)

    if args.config:
        cfg_text = args.config.read_text(encoding="utf-8")
        hardening_results = audit_cisco_config(cfg_text)

    md_report = render_markdown_report(diag_results, hardening_results)
    print(md_report)

    if args.out_md:
        args.out_md.write_text(md_report, encoding="utf-8")

    if args.out_html:
        html_report = render_html_report(diag_results, hardening_results)
        args.out_html.write_text(html_report, encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Report generator for NetAudit (Markdown and HTML outputs)."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .diagnostics import CheckResult
from .hardening import HardeningFinding


def _compute_score(statuses: list[str]) -> int:
    if not statuses:
        return 100
    passed = sum(1 for s in statuses if s == "PASS")
    return round((passed / len(statuses)) * 100)


def render_markdown_report(
    diagnostics: list[CheckResult],
    hardening: list[HardeningFinding],
    title: str = "NetAudit Security & Diagnostics Report",
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_statuses = [d.status for d in diagnostics] + [h.status for h in hardening]
    score = _compute_score(all_statuses)
    passed = sum(1 for s in all_statuses if s == "PASS")
    warned = sum(1 for s in all_statuses if s == "WARN")
    failed = sum(1 for s in all_statuses if s == "FAIL")

    lines = [
        f"# {title}",
        "",
        f"**Generated:** {timestamp}  ",
        f"**Overall Compliance Score:** {score}% ({passed} PASS / {warned} WARN / {failed} FAIL)",
        "",
    ]

    if diagnostics:
        lines.extend(
            [
                "## 1. Network Diagnostics",
                "",
                "| Check | Target | Status | Latency (ms) | Detail |",
                "| :--- | :--- | :--- | ---: | :--- |",
            ]
        )
        for item in diagnostics:
            lat = f"{item.latency_ms:.2f}" if item.latency_ms is not None else "-"
            lines.append(f"| {item.name} | `{item.target}` | **{item.status}** | {lat} | {item.detail} |")
        lines.append("")

    if hardening:
        lines.extend(
            [
                "## 2. Cisco IOS Hardening Audit",
                "",
                "| Rule ID | Control | Severity | Status | Finding | Remediation |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for h in hardening:
            lines.append(
                f"| `{h.rule_id}` | {h.title} | {h.severity} | **{h.status}** | {h.detail} | {h.remediation} |"
            )
        lines.append("")

    return "\n".join(lines)


def render_html_report(
    diagnostics: list[CheckResult],
    hardening: list[HardeningFinding],
    title: str = "NetAudit Security & Diagnostics Report",
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_statuses = [d.status for d in diagnostics] + [h.status for h in hardening]
    score = _compute_score(all_statuses)
    passed = sum(1 for s in all_statuses if s == "PASS")
    warned = sum(1 for s in all_statuses if s == "WARN")
    failed = sum(1 for s in all_statuses if s == "FAIL")

    def badge(status: str) -> str:
        colors = {"PASS": "#16a34a", "WARN": "#d97706", "FAIL": "#dc2626"}
        bg = colors.get(status, "#475569")
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">{html.escape(status)}</span>'

    diag_rows = "\n".join(
        f"<tr><td>{html.escape(d.name)}</td><td><code>{html.escape(d.target)}</code></td>"
        f"<td>{badge(d.status)}</td><td>{f'{d.latency_ms:.2f}' if d.latency_ms is not None else '-'}</td>"
        f"<td>{html.escape(d.detail)}</td></tr>"
        for d in diagnostics
    )

    hard_rows = "\n".join(
        f"<tr><td><code>{html.escape(h.rule_id)}</code></td><td>{html.escape(h.title)}</td>"
        f"<td>{html.escape(h.severity)}</td><td>{badge(h.status)}</td>"
        f"<td>{html.escape(h.detail)}</td><td>{html.escape(h.remediation)}</td></tr>"
        for h in hardening
    )

    diag_section = (
        f"<h2>Network Diagnostics</h2><table><thead><tr><th>Check</th><th>Target</th><th>Status</th><th>Latency (ms)</th><th>Detail</th></tr></thead><tbody>{diag_rows}</tbody></table>"
        if diagnostics
        else ""
    )
    hard_section = (
        f"<h2>Cisco IOS Hardening Audit</h2><table><thead><tr><th>Rule ID</th><th>Control</th><th>Severity</th><th>Status</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>{hard_rows}</tbody></table>"
        if hardening
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 32px; background: #f8fafc; color: #0f172a; }}
  .container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 28px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); }}
  h1 {{ margin-top: 0; font-size: 24px; }}
  .meta {{ color: #475569; font-size: 14px; margin-bottom: 20px; }}
  .kpis {{ display: flex; gap: 16px; margin-bottom: 24px; }}
  .kpi {{ background: #f1f5f9; padding: 14px 18px; border-radius: 8px; flex: 1; }}
  .kpi strong {{ display: block; font-size: 22px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 28px; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <h1>{html.escape(title)}</h1>
  <div class="meta">Generated: {html.escape(timestamp)}</div>
  <div class="kpis">
    <div class="kpi"><span>Compliance Score</span><strong>{score}%</strong></div>
    <div class="kpi"><span>Passed</span><strong style="color:#16a34a;">{passed}</strong></div>
    <div class="kpi"><span>Warnings</span><strong style="color:#d97706;">{warned}</strong></div>
    <div class="kpi"><span>Failed</span><strong style="color:#dc2626;">{failed}</strong></div>
  </div>
  {diag_section}
  {hard_section}
</div>
</body>
</html>
"""

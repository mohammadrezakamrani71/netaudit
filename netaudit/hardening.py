"""Cisco IOS / IOS-XE configuration security hardening auditor."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class HardeningFinding:
    rule_id: str
    title: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    status: str    # "PASS", "FAIL", "WARN"
    detail: str
    remediation: str


def audit_cisco_config(config_text: str) -> list[HardeningFinding]:
    """Audit a Cisco IOS running-config string against baseline security hardening rules."""
    lines = [line.rstrip() for line in config_text.splitlines()]
    joined = "\n".join(lines)
    findings: list[HardeningFinding] = []

    # 1. Password encryption service
    if re.search(r"^\s*service\s+password-encryption\b", joined, re.MULTILINE):
        findings.append(
            HardeningFinding(
                rule_id="CISCO-001",
                title="Service Password Encryption",
                severity="MEDIUM",
                status="PASS",
                detail="`service password-encryption` is enabled.",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-001",
                title="Service Password Encryption",
                severity="MEDIUM",
                status="FAIL",
                detail="`service password-encryption` is missing; local passwords may be stored in plaintext.",
                remediation="Run: `service password-encryption` in global configuration mode.",
            )
        )

    # 2. Enable secret vs legacy enable password
    has_enable_secret = bool(re.search(r"^\s*enable\s+secret\b", joined, re.MULTILINE))
    has_enable_password = bool(re.search(r"^\s*enable\s+password\b", joined, re.MULTILINE))
    if has_enable_secret and not has_enable_password:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-002",
                title="Privileged Exec Secret Protection",
                severity="HIGH",
                status="PASS",
                detail="`enable secret` is configured without legacy `enable password`.",
                remediation="No action required.",
            )
        )
    elif has_enable_password:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-002",
                title="Privileged Exec Secret Protection",
                severity="HIGH",
                status="FAIL",
                detail="Legacy `enable password` detected (weak/plaintext type 0 or type 7).",
                remediation="Run: `no enable password` and configure `enable secret <strong-secret>`.",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-002",
                title="Privileged Exec Secret Protection",
                severity="HIGH",
                status="WARN",
                detail="Neither `enable secret` nor `enable password` was found in the config.",
                remediation="Configure `enable secret <strong-secret>`.",
            )
        )

    # 3. SSH version 2
    if re.search(r"^\s*ip\s+ssh\s+version\s+2\b", joined, re.MULTILINE):
        findings.append(
            HardeningFinding(
                rule_id="CISCO-003",
                title="SSHv2 Enforcement",
                severity="HIGH",
                status="PASS",
                detail="`ip ssh version 2` is enforced.",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-003",
                title="SSHv2 Enforcement",
                severity="HIGH",
                status="FAIL",
                detail="`ip ssh version 2` is not configured; device may allow deprecated SSHv1.",
                remediation="Configure `ip domain-name <domain>`, generate RSA keys (>=2048), and run `ip ssh version 2`.",
            )
        )

    # 4. VTY transport input (disallow telnet / all)
    vty_blocks = re.findall(r"line\s+vty\s+[^\n]+(?:\n\s+[^\n]+)*", joined)
    if not vty_blocks:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-004",
                title="VTY Line Transport Security",
                severity="HIGH",
                status="WARN",
                detail="No `line vty` configuration block found.",
                remediation="Configure `line vty 0 4` with `transport input ssh` and `login local`.",
            )
        )
    else:
        insecure_vty = any(
            re.search(r"transport\s+input\s+(?:.*telnet|all)\b", blk) or "transport input" not in blk
            for blk in vty_blocks
        )
        if insecure_vty:
            findings.append(
                HardeningFinding(
                    rule_id="CISCO-004",
                    title="VTY Line Transport Security",
                    severity="HIGH",
                    status="FAIL",
                    detail="One or more `line vty` blocks permit Telnet or do not restrict `transport input ssh`.",
                    remediation="Under `line vty`, run: `transport input ssh` and `login local`.",
                )
            )
        else:
            findings.append(
                HardeningFinding(
                    rule_id="CISCO-004",
                    title="VTY Line Transport Security",
                    severity="HIGH",
                    status="PASS",
                    detail="All `line vty` blocks restrict management access to SSH only.",
                    remediation="No action required.",
                )
            )

    # 5. Unencrypted HTTP server disabled
    if re.search(r"^\s*ip\s+http\s+server\b", joined, re.MULTILINE) and not re.search(
        r"^\s*no\s+ip\s+http\s+server\b", joined, re.MULTILINE
    ):
        findings.append(
            HardeningFinding(
                rule_id="CISCO-005",
                title="Disable Unencrypted HTTP Management",
                severity="MEDIUM",
                status="FAIL",
                detail="`ip http server` is enabled without `no ip http server`, exposing plaintext web management.",
                remediation="Run: `no ip http server` (and use `ip http secure-server` only if HTTPS GUI is required).",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-005",
                title="Disable Unencrypted HTTP Management",
                severity="MEDIUM",
                status="PASS",
                detail="Unencrypted HTTP management server is disabled.",
                remediation="No action required.",
            )
        )

    # 6. Central Syslog / Logging configured
    if re.search(r"^\s*logging\s+(?:host\s+)?\d+\.\d+\.\d+\.\d+", joined, re.MULTILINE):
        findings.append(
            HardeningFinding(
                rule_id="CISCO-006",
                title="Centralized Syslog Forwarding",
                severity="LOW",
                status="PASS",
                detail="Remote Syslog server target is configured.",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-006",
                title="Centralized Syslog Forwarding",
                severity="LOW",
                status="WARN",
                detail="No remote Syslog server IP detected; logs are only stored locally.",
                remediation="Configure `logging host <syslog-server-ip>` and `service timestamps log datetime msec`.",
            )
        )

    # 7. Login Banner
    if re.search(r"^\s*banner\s+(?:motd|login)\b", joined, re.MULTILINE):
        findings.append(
            HardeningFinding(
                rule_id="CISCO-007",
                title="Authorized Access Banner",
                severity="LOW",
                status="PASS",
                detail="Login/MOTD warning banner is configured.",
                remediation="No action required.",
            )
        )
    else:
        findings.append(
            HardeningFinding(
                rule_id="CISCO-007",
                title="Authorized Access Banner",
                severity="LOW",
                status="WARN",
                detail="No `banner motd` or `banner login` configured.",
                remediation="Configure `banner motd # Authorized access only. #`.",
            )
        )

    return findings

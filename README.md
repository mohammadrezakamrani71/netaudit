# NetAudit — Automated Network Diagnostics & Cisco IOS Hardening Auditor

**NetAudit** is a zero-dependency Python CLI tool designed for network engineers and security analysts to automate baseline network diagnostics, CIDR subnet validation, and offline Cisco IOS/IOS-XE configuration security hardening audits.

## Key Features

- **Network Diagnostics (`netaudit/diagnostics.py`)**
  - **DNS Resolution:** Verifies forward DNS lookups and measures resolution latency.
  - **TCP Port Reachability:** Tests service availability and connection latency on target ports.
  - **TLS/SSL Inspection:** Checks active TLS protocol versions and flags expiring or expired certificates.
  - **CIDR & Subnet Analysis:** Validates IPv4/IPv6 CIDR notation, calculates usable host counts, and detects overlapping subnets.
- **Cisco IOS Security Hardening Auditor (`netaudit/hardening.py`)**
  - Audits running-configuration files offline against baseline hardening controls:
    - `CISCO-001`: `service password-encryption` enabled
    - `CISCO-002`: `enable secret` used instead of legacy `enable password`
    - `CISCO-003`: `ip ssh version 2` enforced
    - `CISCO-004`: `line vty` restricted to `transport input ssh` (flags `telnet` or `all`)
    - `CISCO-005`: Unencrypted `ip http server` disabled
    - `CISCO-006`: Centralized Syslog server configured
    - `CISCO-007`: Authorized access login/MOTD banner configured
  - Outputs actionable CLI remediation commands for every failed or warning control.
- **Automated Reporting (`netaudit/reporter.py`)**
  - Generates structured **Markdown (`.md`)** and standalone **HTML (`.html`)** audit reports with an overall compliance score.

## Project Structure

```text
netaudit/
├── main.py
├── netaudit/
│   ├── __init__.py
│   ├── cli.py
│   ├── diagnostics.py
│   ├── hardening.py
│   └── reporter.py
├── samples/
│   ├── router_sample.cfg
│   └── targets.json
├── tests/
│   └── test_netaudit.py
├── LICENSE
└── README.md
```

## Quick Start

Requires **Python 3.10+** (uses only the Python standard library — no external packages needed).

Run both network diagnostics and a Cisco config hardening audit:

```bash
python3 main.py \
  --targets samples/targets.json \
  --config samples/router_sample.cfg \
  --out-md audit_report.md \
  --out-html audit_report.html
```

Run only a Cisco configuration audit:

```bash
python3 main.py --config samples/router_sample.cfg --out-html report.html
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

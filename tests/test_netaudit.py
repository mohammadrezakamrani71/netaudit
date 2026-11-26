"""Unit tests for NetAudit diagnostics, Cisco hardening auditor, and reporting."""

import unittest

from netaudit.diagnostics import analyze_subnets, check_dns
from netaudit.hardening import audit_cisco_config
from netaudit.reporter import render_html_report, render_markdown_report


class TestDiagnostics(unittest.TestCase):
    def test_subnet_overlap_detection(self) -> None:
        results = analyze_subnets(["10.0.0.0/24", "10.0.0.128/25"])
        overlaps = [r for r in results if r.name == "Subnet Overlap Check"]
        self.assertEqual(len(overlaps), 1)
        self.assertEqual(overlaps[0].status, "FAIL")

    def test_valid_disjoint_subnets(self) -> None:
        results = analyze_subnets(["10.10.1.0/24", "10.10.2.0/24"])
        self.assertTrue(all(r.status == "PASS" for r in results))

    def test_dns_localhost(self) -> None:
        res = check_dns("localhost")
        self.assertEqual(res.status, "PASS")


class TestHardening(unittest.TestCase):
    def test_insecure_config_flags_failures(self) -> None:
        cfg = """
        hostname TEST-R1
        enable password weakpass
        ip http server
        line vty 0 4
         transport input telnet
        """
        findings = {f.rule_id: f for f in audit_cisco_config(cfg)}
        self.assertEqual(findings["CISCO-001"].status, "FAIL")
        self.assertEqual(findings["CISCO-002"].status, "FAIL")
        self.assertEqual(findings["CISCO-003"].status, "FAIL")
        self.assertEqual(findings["CISCO-004"].status, "FAIL")
        self.assertEqual(findings["CISCO-005"].status, "FAIL")

    def test_hardened_config_passes(self) -> None:
        cfg = """
        hostname SECURE-R1
        service password-encryption
        enable secret 9 $9$StrongHashHere
        ip ssh version 2
        no ip http server
        logging host 10.10.10.50
        banner motd # Authorized access only. #
        line vty 0 4
         login local
         transport input ssh
        """
        findings = audit_cisco_config(cfg)
        self.assertTrue(all(f.status == "PASS" for f in findings))


class TestReporter(unittest.TestCase):
    def test_markdown_and_html_generation(self) -> None:
        diag = analyze_subnets(["192.168.1.0/24"])
        hard = audit_cisco_config("service password-encryption\nip ssh version 2\n")
        md = render_markdown_report(diag, hard)
        html_out = render_html_report(diag, hard)
        self.assertIn("NetAudit Security & Diagnostics Report", md)
        self.assertIn("<!DOCTYPE html>", html_out)


if __name__ == "__main__":
    unittest.main()

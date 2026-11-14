"""Unit tests for SecureCommit scoring engine."""

import unittest
from securecommit.reports.scoring import calculate_security_score, format_scoring_explanation
from securecommit.utils.config import SeverityLevel, VulnerabilityCategory, VulnerabilityFinding


class TestScoring(unittest.TestCase):
    def test_clean_scan_receives_100(self):
        score, counts = calculate_security_score([])
        self.assertEqual(score, 100)
        self.assertEqual(counts[SeverityLevel.CRITICAL], 0)
        self.assertEqual(counts[SeverityLevel.HIGH], 0)
        self.assertEqual(counts[SeverityLevel.MEDIUM], 0)
        self.assertEqual(counts[SeverityLevel.LOW], 0)

    def test_severity_weights_deduction(self):
        # 1 Critical (-10), 1 High (-7), 1 Medium (-4), 1 Low (-1) = -22 penalty -> 78
        findings = [
            VulnerabilityFinding(
                id="f1", title="RCE", category=VulnerabilityCategory.SAST,
                severity=SeverityLevel.CRITICAL, file_path="app.py",
                scanner="semgrep", rule_id="cwe-78", description="Command injection"
            ),
            VulnerabilityFinding(
                id="f2", title="SQLi", category=VulnerabilityCategory.SAST,
                severity=SeverityLevel.HIGH, file_path="db.py",
                scanner="semgrep", rule_id="cwe-89", description="SQL injection"
            ),
            VulnerabilityFinding(
                id="f3", title="XSS", category=VulnerabilityCategory.SAST,
                severity=SeverityLevel.MEDIUM, file_path="views.py",
                scanner="semgrep", rule_id="cwe-79", description="XSS"
            ),
            VulnerabilityFinding(
                id="f4", title="Config", category=VulnerabilityCategory.CONFIG,
                severity=SeverityLevel.LOW, file_path="Dockerfile",
                scanner="trivy", rule_id="DS026", description="Missing healthcheck"
            ),
        ]
        score, counts = calculate_security_score(findings)
        self.assertEqual(counts[SeverityLevel.CRITICAL], 1)
        self.assertEqual(counts[SeverityLevel.HIGH], 1)
        self.assertEqual(counts[SeverityLevel.MEDIUM], 1)
        self.assertEqual(counts[SeverityLevel.LOW], 1)
        self.assertEqual(score, 78)

    def test_score_floor_is_zero(self):
        # 12 Critical findings: 12 * 10 = 120 -> score max(0, 100 - 120) = 0
        findings = [
            VulnerabilityFinding(
                id=f"f{i}", title="Crit", category=VulnerabilityCategory.SAST,
                severity=SeverityLevel.CRITICAL, file_path="app.py",
                scanner="semgrep", rule_id="crit", description="Critical"
            )
            for i in range(12)
        ]
        score, _ = calculate_security_score(findings)
        self.assertEqual(score, 0)

    def test_explanation_formatting(self):
        _, counts = calculate_security_score([])
        explanation = format_scoring_explanation(100, counts)
        self.assertIn("Base Score: 100", explanation)
        self.assertIn("Final Security Score: 100/100", explanation)


if __name__ == "__main__":
    unittest.main()

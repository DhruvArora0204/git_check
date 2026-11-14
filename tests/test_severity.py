"""Unit tests for severity normalization and sorting."""

import unittest
from securecommit.reports.severity import (
    normalize_cvss_score,
    normalize_gitleaks_severity,
    normalize_semgrep_severity,
    normalize_trivy_severity,
    sort_findings_by_severity,
)
from securecommit.utils.config import SeverityLevel, VulnerabilityCategory, VulnerabilityFinding


class TestSeverity(unittest.TestCase):
    def test_normalize_semgrep_severity(self):
        # Critical detection keywords
        self.assertEqual(
            normalize_semgrep_severity("ERROR", "python-command-injection", "Command injection via os.system"),
            SeverityLevel.CRITICAL,
        )
        # High detection keywords
        self.assertEqual(
            normalize_semgrep_severity("ERROR", "python-sql-injection", "SQL injection detected"),
            SeverityLevel.HIGH,
        )
        # Medium
        self.assertEqual(
            normalize_semgrep_severity("WARNING", "python-xss", "Cross-site scripting"),
            SeverityLevel.MEDIUM,
        )
        # Low
        self.assertEqual(
            normalize_semgrep_severity("INFO", "python-style", "Minor style issue"),
            SeverityLevel.LOW,
        )

    def test_normalize_cvss_score(self):
        self.assertEqual(normalize_cvss_score(9.8), SeverityLevel.CRITICAL)
        self.assertEqual(normalize_cvss_score(7.5), SeverityLevel.HIGH)
        self.assertEqual(normalize_cvss_score(5.4), SeverityLevel.MEDIUM)
        self.assertEqual(normalize_cvss_score(2.1), SeverityLevel.LOW)

    def test_normalize_gitleaks_severity(self):
        self.assertEqual(normalize_gitleaks_severity("rsa-private-key"), SeverityLevel.CRITICAL)
        self.assertEqual(normalize_gitleaks_severity("github-pat"), SeverityLevel.HIGH)

    def test_normalize_trivy_severity(self):
        self.assertEqual(normalize_trivy_severity("CRITICAL"), SeverityLevel.CRITICAL)
        self.assertEqual(normalize_trivy_severity("HIGH"), SeverityLevel.HIGH)
        self.assertEqual(normalize_trivy_severity("MEDIUM"), SeverityLevel.MEDIUM)
        self.assertEqual(normalize_trivy_severity("LOW"), SeverityLevel.LOW)

    def test_sort_findings_descending(self):
        f_low = VulnerabilityFinding(
            id="1", title="Low Issue", category=VulnerabilityCategory.CONFIG,
            severity=SeverityLevel.LOW, file_path="c.py", scanner="trivy",
            rule_id="r1", description="desc"
        )
        f_crit = VulnerabilityFinding(
            id="2", title="Crit Issue", category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.CRITICAL, file_path="a.py", scanner="semgrep",
            rule_id="r2", description="desc"
        )
        f_high = VulnerabilityFinding(
            id="3", title="High Issue", category=VulnerabilityCategory.SECRET,
            severity=SeverityLevel.HIGH, file_path="b.py", scanner="gitleaks",
            rule_id="r3", description="desc"
        )
        f_med = VulnerabilityFinding(
            id="4", title="Med Issue", category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.MEDIUM, file_path="d.py", scanner="semgrep",
            rule_id="r4", description="desc"
        )

        sorted_list = sort_findings_by_severity([f_low, f_med, f_crit, f_high])
        self.assertEqual(sorted_list[0].severity, SeverityLevel.CRITICAL)
        self.assertEqual(sorted_list[1].severity, SeverityLevel.HIGH)
        self.assertEqual(sorted_list[2].severity, SeverityLevel.MEDIUM)
        self.assertEqual(sorted_list[3].severity, SeverityLevel.LOW)


if __name__ == "__main__":
    unittest.main()

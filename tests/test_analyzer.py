"""Integration tests for SecurityAnalyzer orchestrator."""

from pathlib import Path
import unittest
from securecommit.scanner.analyzer import SecurityAnalyzer
from securecommit.utils.config import SeverityLevel

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestSecurityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SecurityAnalyzer()

    def test_clean_files_scan_score_100(self):
        clean_file = str(FIXTURES_DIR / "clean_code.py")
        report = self.analyzer.scan_files([clean_file])
        self.assertEqual(report.scanned_files_count, 1)
        self.assertEqual(len(report.vulnerabilities), 0)
        self.assertEqual(report.security_score, 100)

    def test_multi_scanner_findings_and_severity_ranking(self):
        targets = [
            str(FIXTURES_DIR / "vulnerable_code.py"),
            str(FIXTURES_DIR / "vulnerable_secrets.py"),
            str(FIXTURES_DIR / "vulnerable_requirements.txt"),
            str(FIXTURES_DIR / "Dockerfile"),
        ]
        report = self.analyzer.scan_files(targets)

        self.assertEqual(report.scanned_files_count, 4)
        self.assertGreater(len(report.vulnerabilities), 0)
        self.assertLess(report.security_score, 100)

        # Check that vulnerabilities are sorted descending by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
        }
        for i in range(len(report.vulnerabilities) - 1):
            curr_sev = report.vulnerabilities[i].severity
            next_sev = report.vulnerabilities[i + 1].severity
            self.assertLessEqual(
                severity_order[curr_sev],
                severity_order[next_sev],
                f"Findings not sorted by severity: {curr_sev} came before {next_sev}"
            )

        # Verify severity counts sum up to total findings
        total_counted = (
            report.critical_count +
            report.high_count +
            report.medium_count +
            report.low_count
        )
        self.assertEqual(total_counted, len(report.vulnerabilities))

    def test_scanner_statuses_captured(self):
        report = self.analyzer.scan_files([str(FIXTURES_DIR / "clean_code.py")])
        scanner_names = [res.scanner_name for res in report.scanner_results]
        self.assertIn("semgrep", scanner_names)
        self.assertIn("gitleaks", scanner_names)
        self.assertIn("osv-scanner", scanner_names)
        self.assertIn("trivy", scanner_names)


if __name__ == "__main__":
    unittest.main()

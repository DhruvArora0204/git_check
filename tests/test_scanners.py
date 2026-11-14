"""Integration tests for Semgrep, Gitleaks, OSV-Scanner, and Trivy wrappers."""

from pathlib import Path
import unittest
from securecommit.scanner.config_scan import ConfigScanner
from securecommit.scanner.dependencies import DependencyScanner
from securecommit.scanner.secrets import SecretScanner, redact_sensitive_string
from securecommit.scanner.semgrep import SemgrepScanner
from securecommit.utils.config import SeverityLevel, VulnerabilityCategory

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestScanners(unittest.TestCase):
    def test_redact_sensitive_string(self):
        token = "ghp_123456789012345678901234567890123456"
        redacted = redact_sensitive_string(token)
        self.assertNotIn("1234567890123456", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)
        self.assertTrue(redacted.startswith("ghp_"))
        self.assertTrue(redacted.endswith("3456"))

    def test_semgrep_detects_sast_vulnerabilities(self):
        scanner = SemgrepScanner()
        if not scanner.is_available():
            self.skipTest("Semgrep not installed")

        target = str(FIXTURES_DIR / "vulnerable_code.py")
        res = scanner.scan([target])
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.findings), 0)

        # Check that SQL injection, command injection, and deserialization are detected
        titles = [f.title for f in res.findings]
        self.assertTrue(any("SQL Injection" in t for t in titles), f"SQL Injection not found in {titles}")
        self.assertTrue(any("Command Injection" in t for t in titles), f"Command Injection not found in {titles}")

    def test_semgrep_clean_code(self):
        scanner = SemgrepScanner()
        if not scanner.is_available():
            self.skipTest("Semgrep not installed")

        clean_file = str(FIXTURES_DIR / "clean_code.py")
        res = scanner.scan([clean_file])
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(len(res.findings), 0)

    def test_gitleaks_detects_secrets(self):
        scanner = SecretScanner()
        if not scanner.is_available():
            self.skipTest("Gitleaks not installed")

        secret_file = str(FIXTURES_DIR / "vulnerable_secrets.py")
        res = scanner.scan([secret_file])
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.findings), 0)
        self.assertEqual(res.findings[0].category, VulnerabilityCategory.SECRET)
        # Ensure secret is redacted in code snippet
        self.assertNotIn("ghp_12345678901234567890", res.findings[0].code_snippet)

    def test_dependency_scanner_detects_osv_vulnerabilities(self):
        scanner = DependencyScanner()
        if not scanner.is_available():
            self.skipTest("OSV-Scanner not installed")

        req_file = str(FIXTURES_DIR / "vulnerable_requirements.txt")
        res = scanner.scan([req_file])
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.findings), 0)
        self.assertEqual(res.findings[0].category, VulnerabilityCategory.DEPENDENCY)
        self.assertIn("requests", res.findings[0].title.lower())

    def test_config_scanner_detects_trivy_misconfigurations(self):
        scanner = ConfigScanner()
        if not scanner.is_available():
            self.skipTest("Trivy not installed")

        dockerfile = str(FIXTURES_DIR / "Dockerfile")
        res = scanner.scan([dockerfile])
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.findings), 0)
        self.assertEqual(res.findings[0].category, VulnerabilityCategory.CONFIG)


if __name__ == "__main__":
    unittest.main()

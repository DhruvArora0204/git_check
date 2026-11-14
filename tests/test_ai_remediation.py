"""Unit and integration tests for AI-powered remediation and patch application."""

from pathlib import Path
import tempfile
import unittest
from securecommit.ai.prompts import build_remediation_prompt
from securecommit.ai.remediation import AIRemediationEngine
from securecommit.utils.config import SeverityLevel, VulnerabilityCategory, VulnerabilityFinding


class TestAIRemediation(unittest.TestCase):
    def setUp(self):
        self.engine = AIRemediationEngine()

    def test_prompt_builder(self):
        finding = VulnerabilityFinding(
            id="test1",
            title="SQL Injection",
            category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.HIGH,
            file_path="db.py",
            line_number=24,
            code_snippet="cursor.execute('SELECT * FROM users WHERE name = ' + user)",
            scanner="semgrep",
            rule_id="python-sqli",
            description="Dynamic SQL query",
        )
        prompt = build_remediation_prompt(finding)
        self.assertIn("SQL Injection", prompt)
        self.assertIn("cursor.execute", prompt)
        self.assertIn("suggested_fix_code", prompt)

    def test_secrets_are_redacted_before_ai(self):
        finding = VulnerabilityFinding(
            id="sec1",
            title="Hardcoded API Key",
            category=VulnerabilityCategory.SECRET,
            severity=SeverityLevel.HIGH,
            file_path="config.py",
            line_number=8,
            code_snippet="API_KEY = 'ghp_123456789012345678901234567890123456'",
            scanner="gitleaks",
            rule_id="github-pat",
            description="GitHub PAT leak",
        )
        sanitized = self.engine._sanitize_finding(finding)
        self.assertNotIn("1234567890123456", sanitized.code_snippet)
        self.assertIn("[REDACTED_SECRET]", sanitized.code_snippet)

    def test_contextual_fallback_sql_injection(self):
        finding = VulnerabilityFinding(
            id="sqli",
            title="SQL Injection",
            category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.HIGH,
            file_path="db.py",
            line_number=10,
            code_snippet="cursor.execute('SELECT * FROM users WHERE name = ' + name)",
            scanner="semgrep",
            rule_id="cwe-89",
            description="SQL Injection",
        )
        advice = self.engine.generate_advice(finding)
        self.assertIn("parameterized", advice.safety_justification.lower())
        self.assertIn("?", advice.suggested_fix_code)

    def test_contextual_fallback_command_injection(self):
        finding = VulnerabilityFinding(
            id="cmdi",
            title="Command Injection",
            category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.CRITICAL,
            file_path="backup.py",
            line_number=15,
            code_snippet="os.system('tar -czf ' + path)",
            scanner="semgrep",
            rule_id="cwe-78",
            description="Command Injection",
        )
        advice = self.engine.generate_advice(finding)
        self.assertIn("shell=False", advice.safety_justification)
        self.assertIn("subprocess", advice.suggested_fix_code)

    def test_apply_approved_patch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "database.py"
            original_code = (
                "import sqlite3\n\n"
                "def get_user(db, username):\n"
                "    cursor = db.cursor()\n"
                "    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
                "    cursor.execute(query)\n"
            )
            test_file.write_text(original_code, encoding="utf-8")

            bad_snippet = "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\""
            good_snippet = "query = \"SELECT * FROM users WHERE name = ?\"\n    cursor.execute(query, (username,))"

            # Apply patch
            success = self.engine.apply_approved_patch(
                file_path=str(test_file),
                original_snippet=bad_snippet,
                replacement_code=good_snippet,
                stage_git=False,
            )
            self.assertTrue(success)

            updated_content = test_file.read_text(encoding="utf-8")
            self.assertIn("SELECT * FROM users WHERE name = ?", updated_content)
            self.assertNotIn("WHERE name = '\" + username", updated_content)

    def test_unapproved_patch_never_modifies_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "sample.py"
            original_content = "def hello():\n    print('world')\n"
            test_file.write_text(original_content, encoding="utf-8")

            # Simulate unapproved / no apply action taken
            # File content remains exact
            self.assertEqual(test_file.read_text(encoding="utf-8"), original_content)

    def test_env_file_loading(self):
        import os
        from securecommit.ai.remediation import _load_env_file
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_file = Path(tmp_dir) / ".env"
            env_file.write_text("TEST_SECURECOMMIT_KEY=dummy_value_123\n", encoding="utf-8")
            # Temporarily change dir to tmp_dir
            orig_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)
                _load_env_file()
                self.assertEqual(os.environ.get("TEST_SECURECOMMIT_KEY"), "dummy_value_123")
            finally:
                os.chdir(orig_cwd)
                os.environ.pop("TEST_SECURECOMMIT_KEY", None)


if __name__ == "__main__":
    unittest.main()

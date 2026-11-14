"""Unit and integration tests for Git pre-commit hook integration."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from securecommit.git.hooks import install_hook, prompt_developer_decision, run_pre_commit_hook, uninstall_hook
from securecommit.git.staged_files import get_git_root, get_staged_files, is_git_repository
from securecommit.utils.config import ScanReport, SeverityLevel, VulnerabilityCategory, VulnerabilityFinding


class TestGitIntegration(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory and initialize a clean git repo
        self.test_dir = tempfile.mkdtemp()
        subprocess.run(["git", "init"], cwd=self.test_dir, capture_output=True, check=True)
        # Configure test git identity
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.test_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.test_dir, check=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_is_git_repository(self):
        self.assertTrue(is_git_repository(self.test_dir))
        non_git = tempfile.mkdtemp()
        try:
            self.assertFalse(is_git_repository(non_git))
        finally:
            shutil.rmtree(non_git, ignore_errors=True)

    def test_get_git_root(self):
        root = get_git_root(self.test_dir)
        self.assertIsNotNone(root)
        self.assertEqual(root.resolve(), Path(self.test_dir).resolve())

    def test_get_staged_files(self):
        file1 = Path(self.test_dir) / "app.py"
        file1.write_text("print('hello')", encoding="utf-8")

        # Before staging
        staged = get_staged_files(self.test_dir)
        self.assertEqual(len(staged), 0)

        # Stage file
        subprocess.run(["git", "add", "app.py"], cwd=self.test_dir, check=True)
        staged = get_staged_files(self.test_dir)
        self.assertEqual(len(staged), 1)
        self.assertEqual(Path(staged[0]).resolve(), file1.resolve())

    def test_hook_install_and_uninstall(self):
        hook_path = Path(self.test_dir) / ".git" / "hooks" / "pre-commit"
        self.assertFalse(hook_path.exists())

        # Install
        installed = install_hook(self.test_dir)
        self.assertTrue(installed)
        self.assertTrue(hook_path.exists())
        content = hook_path.read_text(encoding="utf-8")
        self.assertIn("securecommit", content)

        # Uninstall
        uninstalled = uninstall_hook(self.test_dir)
        self.assertTrue(uninstalled)
        self.assertFalse(hook_path.exists())

    def test_clean_commit_flow(self):
        clean_file = Path(self.test_dir) / "clean.py"
        clean_file.write_text("x = 42\n", encoding="utf-8")
        subprocess.run(["git", "add", "clean.py"], cwd=self.test_dir, check=True)

        with patch("securecommit.git.hooks.get_staged_files", return_value=[str(clean_file)]):
            exit_code = run_pre_commit_hook(show_popup=False)
            self.assertEqual(exit_code, 0)

    def test_developer_decision_abort_commit(self):
        dummy_finding = VulnerabilityFinding(
            id="vuln1",
            title="SQL Injection",
            category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.HIGH,
            file_path="app.py",
            scanner="semgrep",
            rule_id="sql-rule",
            description="SQL Injection detected",
        )
        report = ScanReport(
            scanned_files_count=1,
            vulnerabilities=[dummy_finding],
            security_score=93,
            high_count=1,
        )

        # Mock interactive input choosing "3" (Abort commit)
        with patch("sys.stdin.readline", return_value="3"):
            with patch("sys.platform", "unknown"):
                exit_code = prompt_developer_decision(report)
                self.assertEqual(exit_code, 1)

    def test_developer_decision_commit_anyway(self):
        dummy_finding = VulnerabilityFinding(
            id="vuln1",
            title="SQL Injection",
            category=VulnerabilityCategory.SAST,
            severity=SeverityLevel.HIGH,
            file_path="app.py",
            scanner="semgrep",
            rule_id="sql-rule",
            description="SQL Injection detected",
        )
        report = ScanReport(
            scanned_files_count=1,
            vulnerabilities=[dummy_finding],
            security_score=93,
            high_count=1,
        )

        # Mock interactive input choosing "2" (Commit anyway)
        with patch("sys.stdin.readline", return_value="2"):
            with patch("sys.platform", "unknown"):
                exit_code = prompt_developer_decision(report)
                self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()

"""Gitleaks secret detection scanner integration."""

import json
import logging
from pathlib import Path
import subprocess
import tempfile
import time
from typing import List, Optional
from securecommit.reports.severity import normalize_gitleaks_severity
from securecommit.utils.config import (
    SCANNER_TIMEOUT_SECONDS,
    ScannerResult,
    VulnerabilityCategory,
    VulnerabilityFinding,
    find_executable,
    get_augmented_env,
)

logger = logging.getLogger(__name__)


def redact_sensitive_string(raw: str, preserve_chars: int = 4) -> str:
    """Mask sensitive secret values to prevent credential exposure in logs or prompts."""
    if not raw or len(raw) <= preserve_chars * 2:
        return "[REDACTED_SECRET]"
    prefix = raw[:preserve_chars]
    suffix = raw[-preserve_chars:]
    return f"{prefix}...[REDACTED_SECRET]...{suffix}"


class SecretScanner:
    """Wrapper for executing Gitleaks secret detection and normalizing findings."""

    def __init__(self):
        self.executable = find_executable("gitleaks")

    def is_available(self) -> bool:
        """Check if Gitleaks is installed on the host."""
        return self.executable is not None

    def scan(self, target_paths: List[str]) -> ScannerResult:
        """
        Scan specified files or directories for secrets.

        Args:
            target_paths: List of file or directory paths to analyze.
        """
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(
                scanner_name="gitleaks",
                status="SKIPPED",
                findings=[],
                error_message="Gitleaks executable not found. Install via: winget install Gitleaks.Gitleaks",
                duration_seconds=0.0,
            )

        if not target_paths:
            return ScannerResult(
                scanner_name="gitleaks",
                status="SUCCESS",
                findings=[],
                duration_seconds=0.0,
            )

        findings: List[VulnerabilityFinding] = []

        # Create temporary report file
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "gitleaks_report.json"

            for target in target_paths:
                target_p = Path(target)
                if not target_p.exists():
                    continue

                cmd = [
                    self.executable,
                    "dir",
                    str(target_p),
                    "--report-format", "json",
                    "--report-path", str(report_file),
                    "--no-banner",
                    "--exit-code", "0",
                ]

                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=SCANNER_TIMEOUT_SECONDS,
                        env=get_augmented_env(),
                    )
                except subprocess.TimeoutExpired:
                    return ScannerResult(
                        scanner_name="gitleaks",
                        status="ERROR",
                        findings=findings,
                        error_message=f"Gitleaks timed out after {SCANNER_TIMEOUT_SECONDS}s",
                        duration_seconds=time.time() - start_time,
                    )
                except Exception as e:
                    return ScannerResult(
                        scanner_name="gitleaks",
                        status="ERROR",
                        findings=findings,
                        error_message=f"Failed to execute Gitleaks: {str(e)}",
                        duration_seconds=time.time() - start_time,
                    )

                if report_file.exists() and report_file.stat().st_size > 0:
                    try:
                        data = json.loads(report_file.read_text(encoding="utf-8"))
                        if isinstance(data, list):
                            for item in data:
                                finding = self._parse_item(item)
                                if finding:
                                    findings.append(finding)
                    except json.JSONDecodeError as err:
                        logger.warning(f"Error parsing Gitleaks report: {err}")

        return ScannerResult(
            scanner_name="gitleaks",
            status="SUCCESS",
            findings=findings,
            duration_seconds=time.time() - start_time,
        )

    def _parse_item(self, item: dict) -> Optional[VulnerabilityFinding]:
        """Convert a Gitleaks JSON finding into normalized VulnerabilityFinding."""
        rule_id = item.get("RuleID", "exposed-secret")
        desc = item.get("Description", "Hardcoded secret or credential detected")
        file_path = item.get("File", "")
        start_line = item.get("StartLine")
        end_line = item.get("EndLine", start_line)
        secret_val = item.get("Secret", "")
        match_val = item.get("Match", "")

        redacted_match = match_val
        if secret_val and secret_val in redacted_match:
            redacted_match = redacted_match.replace(secret_val, redact_sensitive_string(secret_val))
        elif match_val:
            redacted_match = redact_sensitive_string(match_val)

        title = self._format_title(rule_id, desc)
        severity = normalize_gitleaks_severity(rule_id, desc)

        return VulnerabilityFinding(
            id=VulnerabilityFinding.generate_id("gitleaks", file_path, start_line, rule_id),
            title=title,
            category=VulnerabilityCategory.SECRET,
            severity=severity,
            file_path=file_path,
            line_number=start_line,
            end_line_number=end_line,
            code_snippet=redacted_match or f"# Detected secret matching rule {rule_id}",
            scanner="gitleaks",
            rule_id=rule_id,
            description=desc,
            ai_fix_available=True,
        )

    def _format_title(self, rule_id: str, desc: str) -> str:
        """Derive readable title for secret type."""
        r_lower = rule_id.lower()
        if "api-key" in r_lower or "apikey" in r_lower:
            return "Hardcoded API Key"
        if "token" in r_lower:
            return "Exposed Access Token"
        if "password" in r_lower or "pwd" in r_lower:
            return "Hardcoded Password"
        if "private-key" in r_lower or "rsa" in r_lower:
            return "Exposed Private Key"
        if "aws" in r_lower:
            return "Hardcoded AWS Credential"
        if "github" in r_lower:
            return "Hardcoded GitHub Token"
        return "Exposed Secret / Credential"

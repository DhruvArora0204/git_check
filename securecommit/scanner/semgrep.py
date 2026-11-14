"""Semgrep SAST scanner integration."""

import json
import logging
from pathlib import Path
import subprocess
import time
from typing import List, Optional
from securecommit.reports.severity import normalize_semgrep_severity
from securecommit.utils.config import (
    SCANNER_TIMEOUT_SECONDS,
    ScannerResult,
    SeverityLevel,
    VulnerabilityCategory,
    VulnerabilityFinding,
    find_executable,
    get_augmented_env,
)

logger = logging.getLogger(__name__)


class SemgrepScanner:
    """Wrapper for executing Semgrep static analysis and normalizing findings."""

    def __init__(self, custom_rule_path: Optional[str] = None):
        self.executable = find_executable("semgrep")
        self.default_rules = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"
        self.custom_rule_path = Path(custom_rule_path) if custom_rule_path else None

    def is_available(self) -> bool:
        """Check if Semgrep is installed and executable on the host."""
        return self.executable is not None

    def scan(self, target_paths: List[str]) -> ScannerResult:
        """
        Scan specified files or directories with Semgrep.

        Args:
            target_paths: List of file or directory paths to analyze.
        """
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(
                scanner_name="semgrep",
                status="SKIPPED",
                findings=[],
                error_message="Semgrep executable not found. Install via: pip install semgrep",
                duration_seconds=0.0,
            )

        if not target_paths:
            return ScannerResult(
                scanner_name="semgrep",
                status="SUCCESS",
                findings=[],
                duration_seconds=0.0,
            )

        # Build semgrep command
        cmd = [
            self.executable,
            "scan",
            "--json",
            "--quiet",
            "--no-git-ignore",
        ]

        # Use bundled custom rules and any user-specified rules
        if self.default_rules.exists():
            cmd.extend(["--config", str(self.default_rules)])
        else:
            cmd.extend(["--config", "auto"])

        if self.custom_rule_path and self.custom_rule_path.exists():
            cmd.extend(["--config", str(self.custom_rule_path)])

        # Append targets
        cmd.extend(target_paths)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCANNER_TIMEOUT_SECONDS,
                env=get_augmented_env(),
            )
        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name="semgrep",
                status="ERROR",
                findings=[],
                error_message=f"Semgrep timed out after {SCANNER_TIMEOUT_SECONDS}s",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return ScannerResult(
                scanner_name="semgrep",
                status="ERROR",
                findings=[],
                error_message=f"Failed to execute Semgrep: {str(e)}",
                duration_seconds=time.time() - start_time,
            )

        output_str = result.stdout.strip()
        if not output_str and result.stderr:
            return ScannerResult(
                scanner_name="semgrep",
                status="ERROR",
                findings=[],
                error_message=f"Semgrep execution error: {result.stderr.strip()}",
                duration_seconds=time.time() - start_time,
            )

        try:
            parsed = json.loads(output_str) if output_str else {"results": []}
        except json.JSONDecodeError as err:
            return ScannerResult(
                scanner_name="semgrep",
                status="ERROR",
                findings=[],
                error_message=f"Invalid Semgrep JSON output: {str(err)}",
                duration_seconds=time.time() - start_time,
            )

        findings: List[VulnerabilityFinding] = []
        raw_results = parsed.get("results", [])

        for item in raw_results:
            rule_id = item.get("check_id", "unknown-rule")
            file_path = item.get("path", "")
            start_info = item.get("start", {})
            end_info = item.get("end", {})
            start_line = start_info.get("line")
            end_line = end_info.get("line")
            extra = item.get("extra", {})
            message = extra.get("message", "Security issue detected")
            raw_severity = extra.get("severity", "WARNING")
            lines_snippet = extra.get("lines")

            # Fallback snippet extraction from file if semgrep output says 'requires login' or empty
            if not lines_snippet or "requires login" in str(lines_snippet).lower():
                lines_snippet = self._extract_snippet(file_path, start_line, end_line)

            # Determine title from rule ID
            title = self._format_title(rule_id, message)
            severity = normalize_semgrep_severity(raw_severity, rule_id, message)

            finding = VulnerabilityFinding(
                id=VulnerabilityFinding.generate_id("semgrep", file_path, start_line, rule_id),
                title=title,
                category=VulnerabilityCategory.SAST,
                severity=severity,
                file_path=file_path,
                line_number=start_line,
                end_line_number=end_line,
                code_snippet=lines_snippet,
                scanner="semgrep",
                rule_id=rule_id,
                description=message,
                ai_fix_available=True,
            )
            findings.append(finding)

        return ScannerResult(
            scanner_name="semgrep",
            status="SUCCESS",
            findings=findings,
            duration_seconds=time.time() - start_time,
        )

    def _extract_snippet(self, file_path: str, start_line: Optional[int], end_line: Optional[int]) -> Optional[str]:
        """Extract snippet directly from source file when semgrep lines are unavailable."""
        if not file_path or not start_line:
            return None
        try:
            p = Path(file_path)
            if not p.is_file():
                return None
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            s_idx = max(0, start_line - 1)
            e_idx = max(s_idx + 1, (end_line or start_line))
            return "\n".join(lines[s_idx:e_idx])
        except Exception:
            return None

    def _format_title(self, rule_id: str, message: str) -> str:
        """Derive readable title from rule identifier or message."""
        parts = rule_id.split(".")
        last_part = parts[-1].replace("-", " ").replace("_", " ").title()
        if "Sql" in last_part:
            return "SQL Injection"
        if "Command" in last_part:
            return "Command Injection"
        if "Cross Site Scripting" in last_part or "Xss" in last_part:
            return "Cross-Site Scripting (XSS)"
        if "Deserialization" in last_part:
            return "Insecure Deserialization"
        if "Hash" in last_part or "Crypto" in last_part:
            return "Weak Cryptography"
        return last_part if len(last_part) > 3 else message[:50]

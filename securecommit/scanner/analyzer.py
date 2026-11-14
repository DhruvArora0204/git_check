"""Security scanner orchestrator and analyzer."""

import logging
from pathlib import Path
from typing import List, Optional
from securecommit.reports.scoring import calculate_security_score
from securecommit.reports.severity import sort_findings_by_severity
from securecommit.scanner.config_scan import ConfigScanner
from securecommit.scanner.dependencies import DependencyScanner
from securecommit.scanner.secrets import SecretScanner
from securecommit.scanner.semgrep import SemgrepScanner
from securecommit.utils.config import (
    ScanReport,
    ScannerResult,
    SeverityLevel,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Coordinates all integrated scanners and compiles a normalized security report."""

    def __init__(self, custom_rule_path: Optional[str] = None, auto_install_missing: bool = True):
        self.semgrep_scanner = SemgrepScanner(custom_rule_path=custom_rule_path)
        self.secret_scanner = SecretScanner()
        self.dependency_scanner = DependencyScanner()
        self.config_scanner = ConfigScanner()

        # If any standalone binary is missing, attempt automatic self-healing download
        if auto_install_missing and not (
            self.secret_scanner.is_available()
            and self.dependency_scanner.is_available()
            and self.config_scanner.is_available()
        ):
            try:
                from securecommit.utils.installer import ensure_all_tools
                ensure_all_tools(verbose=False)
                # Re-query binaries in case any were just downloaded
                self.secret_scanner = SecretScanner()
                self.dependency_scanner = DependencyScanner()
                self.config_scanner = ConfigScanner()
            except Exception as e:
                logger.debug(f"Auto-install tools check failed: {e}")

    def scan_files(self, target_files: List[str]) -> ScanReport:
        """
        Analyze the specified target files across all scanners and produce a ScanReport.

        Args:
            target_files: List of file paths to be analyzed.
        """
        clean_targets = [str(Path(f).resolve()) for f in target_files if Path(f).exists()]
        scanned_count = len(clean_targets)

        all_findings: List[VulnerabilityFinding] = []
        scanner_results: List[ScannerResult] = []

        # 1. Run Semgrep SAST
        try:
            res_semgrep = self.semgrep_scanner.scan(clean_targets)
            scanner_results.append(res_semgrep)
            all_findings.extend(res_semgrep.findings)
        except Exception as e:
            scanner_results.append(ScannerResult(
                scanner_name="semgrep",
                status="ERROR",
                error_message=f"Semgrep scanner unhandled error: {str(e)}",
            ))

        # 2. Run Gitleaks Secret Scanner
        try:
            res_secrets = self.secret_scanner.scan(clean_targets)
            scanner_results.append(res_secrets)
            all_findings.extend(res_secrets.findings)
        except Exception as e:
            scanner_results.append(ScannerResult(
                scanner_name="gitleaks",
                status="ERROR",
                error_message=f"Gitleaks scanner unhandled error: {str(e)}",
            ))

        # 3. Run OSV-Scanner Dependency Scanner
        try:
            res_deps = self.dependency_scanner.scan(clean_targets)
            scanner_results.append(res_deps)
            all_findings.extend(res_deps.findings)
        except Exception as e:
            scanner_results.append(ScannerResult(
                scanner_name="osv-scanner",
                status="ERROR",
                error_message=f"OSV-Scanner unhandled error: {str(e)}",
            ))

        # 4. Run Trivy Configuration Scanner
        try:
            res_config = self.config_scanner.scan(clean_targets)
            scanner_results.append(res_config)
            all_findings.extend(res_config.findings)
        except Exception as e:
            scanner_results.append(ScannerResult(
                scanner_name="trivy",
                status="ERROR",
                error_message=f"Trivy scanner unhandled error: {str(e)}",
            ))

        # Deduplicate findings by ID
        unique_findings: List[VulnerabilityFinding] = []
        seen_ids = set()
        for f in all_findings:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                unique_findings.append(f)

        # Sort findings in descending severity order: Critical -> High -> Medium -> Low
        sorted_findings = sort_findings_by_severity(unique_findings)

        # Calculate security score and severity counts
        score, counts = calculate_security_score(sorted_findings)

        return ScanReport(
            scanned_files_count=scanned_count,
            vulnerabilities=sorted_findings,
            security_score=score,
            critical_count=counts.get(SeverityLevel.CRITICAL, 0),
            high_count=counts.get(SeverityLevel.HIGH, 0),
            medium_count=counts.get(SeverityLevel.MEDIUM, 0),
            low_count=counts.get(SeverityLevel.LOW, 0),
            scanner_results=scanner_results,
        )

    def scan_directory(self, directory_path: str = ".") -> ScanReport:
        """Scan all code, secret, dependency, and configuration files within a directory."""
        dir_path = Path(directory_path).resolve()
        if not dir_path.exists():
            return ScanReport(
                scanned_files_count=0,
                vulnerabilities=[],
                security_score=100,
                scanner_results=[ScannerResult(
                    scanner_name="core",
                    status="ERROR",
                    error_message=f"Target directory {directory_path} does not exist",
                )],
            )

        # Find files while skipping .git, virtual environments, and node_modules
        ignored_patterns = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".pytest_cache", ".idea", ".vscode"}
        all_files: List[str] = []
        for root, dirs, files in Path(dir_path).walk():
            dirs[:] = [d for d in dirs if d not in ignored_patterns and not d.startswith(".")]
            for file in files:
                if not file.startswith("."):
                    all_files.append(str(root / file))

        return self.scan_files(all_files)

"""OSV-Scanner dependency vulnerability scanner integration."""

import json
import logging
from pathlib import Path
import subprocess
import time
from typing import List, Optional
from securecommit.reports.severity import normalize_cvss_score
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

# Known dependency manifest/lockfile names
DEPENDENCY_FILE_PATTERNS = {
    "requirements.txt", "requirements.in", "pipfile", "pipfile.lock", "poetry.lock",
    "pyproject.toml", "setup.py", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "pom.xml", "build.gradle", "go.mod", "go.sum", "cargo.toml", "cargo.lock"
}


def is_dependency_file(path_str: str) -> bool:
    """Check if the path corresponds to a dependency manifest or lockfile."""
    name = Path(path_str).name.lower()
    if "requirement" in name and (name.endswith(".txt") or name.endswith(".in")):
        return True
    return name in DEPENDENCY_FILE_PATTERNS or name.endswith(".lock")


class DependencyScanner:
    """Wrapper for executing OSV-Scanner and normalizing dependency vulnerability findings."""

    def __init__(self):
        self.executable = find_executable("osv-scanner")

    def is_available(self) -> bool:
        """Check if OSV-Scanner is installed."""
        return self.executable is not None

    def scan(self, target_paths: List[str]) -> ScannerResult:
        """
        Scan dependency manifests and lockfiles using OSV-Scanner.

        Args:
            target_paths: List of file or directory paths to analyze.
        """
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(
                scanner_name="osv-scanner",
                status="SKIPPED",
                findings=[],
                error_message="OSV-Scanner executable not found. Install via: winget install Google.OSVScanner",
                duration_seconds=0.0,
            )

        # Filter targets to relevant dependency files or directories containing them
        relevant_targets = []
        for tp in target_paths:
            p = Path(tp)
            if p.is_dir() or is_dependency_file(tp):
                relevant_targets.append(tp)

        if not relevant_targets:
            return ScannerResult(
                scanner_name="osv-scanner",
                status="SUCCESS",
                findings=[],
                duration_seconds=time.time() - start_time,
            )

        findings: List[VulnerabilityFinding] = []

        for target in relevant_targets:
            p = Path(target)
            cmd = [self.executable, "scan", "source", "--format", "json"]
            if p.is_dir():
                cmd.extend(["-r", str(p)])
            else:
                cmd.extend(["-L", str(p)])

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
                    scanner_name="osv-scanner",
                    status="ERROR",
                    findings=findings,
                    error_message=f"OSV-Scanner timed out after {SCANNER_TIMEOUT_SECONDS}s",
                    duration_seconds=time.time() - start_time,
                )
            except Exception as e:
                return ScannerResult(
                    scanner_name="osv-scanner",
                    status="ERROR",
                    findings=findings,
                    error_message=f"Failed to execute OSV-Scanner: {str(e)}",
                    duration_seconds=time.time() - start_time,
                )

            stdout = proc.stdout.strip()
            if not stdout:
                continue

            # Strip non-JSON diagnostic prefix lines
            json_start = stdout.find("{")
            if json_start == -1:
                continue
            json_content = stdout[json_start:]

            try:
                data = json.loads(json_content)
                parsed_findings = self._parse_osv_report(data, target)
                findings.extend(parsed_findings)
            except json.JSONDecodeError as err:
                logger.warning(f"Error parsing OSV-Scanner JSON: {err}")

        return ScannerResult(
            scanner_name="osv-scanner",
            status="SUCCESS",
            findings=findings,
            duration_seconds=time.time() - start_time,
        )

    def _parse_osv_report(self, data: dict, fallback_target: str) -> List[VulnerabilityFinding]:
        """Convert OSV-Scanner JSON report into normalized VulnerabilityFindings."""
        results: List[VulnerabilityFinding] = []
        raw_results = data.get("results", [])

        for res in raw_results:
            source_path = res.get("source", {}).get("path", fallback_target)
            packages = res.get("packages", [])

            for pkg_entry in packages:
                pkg_info = pkg_entry.get("package", {})
                pkg_name = pkg_info.get("name", "unknown-package")
                pkg_version = pkg_info.get("version", "")
                groups = pkg_entry.get("groups", [])
                vulns = {v.get("id"): v for v in pkg_entry.get("vulnerabilities", [])}

                for group in groups:
                    group_ids = group.get("ids", [])
                    aliases = group.get("aliases", [])
                    max_sev = group.get("max_severity", "0.0")

                    try:
                        cvss = float(max_sev)
                    except (ValueError, TypeError):
                        cvss = 5.0

                    severity = normalize_cvss_score(cvss)
                    primary_id = aliases[0] if aliases else (group_ids[0] if group_ids else f"{pkg_name}-vuln")

                    # Find matching vuln description
                    summary = ""
                    for gid in group_ids:
                        if gid in vulns:
                            v = vulns[gid]
                            summary = v.get("summary") or v.get("details", "")[:120]
                            break

                    title = f"Vulnerable Dependency: {pkg_name} ({primary_id})"
                    desc = summary or f"Package {pkg_name} {pkg_version} has known security vulnerability {primary_id}."
                    snippet = f"{pkg_name}=={pkg_version}" if pkg_version else pkg_name

                    finding = VulnerabilityFinding(
                        id=VulnerabilityFinding.generate_id("osv-scanner", source_path, None, primary_id),
                        title=title,
                        category=VulnerabilityCategory.DEPENDENCY,
                        severity=severity,
                        file_path=source_path,
                        line_number=None,
                        end_line_number=None,
                        code_snippet=snippet,
                        scanner="osv-scanner",
                        rule_id=primary_id,
                        description=desc,
                        ai_fix_available=True,
                    )
                    results.append(finding)

        return results

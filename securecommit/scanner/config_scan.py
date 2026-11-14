"""Trivy configuration and container security scanner integration."""

import json
import logging
from pathlib import Path
import subprocess
import time
from typing import List, Optional
from securecommit.reports.severity import normalize_trivy_severity
from securecommit.utils.config import (
    SCANNER_TIMEOUT_SECONDS,
    ScannerResult,
    VulnerabilityCategory,
    VulnerabilityFinding,
    find_executable,
    get_augmented_env,
)

logger = logging.getLogger(__name__)

CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".tf", ".hcl", ".toml", ".ini", ".conf", ".xml"
}

CONFIG_FILENAMES = {
    "dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml",
    "k8s.yaml", "k8s.yml", "deployment.yaml", "pod.yaml"
}


def is_config_file(path_str: str) -> bool:
    """Check if the path corresponds to a configuration or container definition file."""
    p = Path(path_str)
    name_lower = p.name.lower()
    if name_lower.startswith("dockerfile") or name_lower in CONFIG_FILENAMES:
        return True
    return p.suffix.lower() in CONFIG_EXTENSIONS


class ConfigScanner:
    """Wrapper for executing Trivy configuration/IaC/container scans and normalizing findings."""

    def __init__(self):
        self.executable = find_executable("trivy")

    def is_available(self) -> bool:
        """Check if Trivy is installed."""
        return self.executable is not None

    def scan(self, target_paths: List[str]) -> ScannerResult:
        """
        Scan configuration files and Dockerfiles using Trivy.

        Args:
            target_paths: List of file or directory paths to analyze.
        """
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(
                scanner_name="trivy",
                status="SKIPPED",
                findings=[],
                error_message="Trivy executable not found. Install via: winget install AquaSecurity.Trivy",
                duration_seconds=0.0,
            )

        # Filter relevant targets
        relevant_targets = []
        for tp in target_paths:
            p = Path(tp)
            if p.is_dir() or is_config_file(tp):
                relevant_targets.append(tp)

        if not relevant_targets:
            return ScannerResult(
                scanner_name="trivy",
                status="SUCCESS",
                findings=[],
                duration_seconds=time.time() - start_time,
            )

        findings: List[VulnerabilityFinding] = []

        for target in relevant_targets:
            cmd = [
                self.executable,
                "config",
                "--format", "json",
                "--quiet",
                str(target),
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
                    scanner_name="trivy",
                    status="ERROR",
                    findings=findings,
                    error_message=f"Trivy timed out after {SCANNER_TIMEOUT_SECONDS}s",
                    duration_seconds=time.time() - start_time,
                )
            except Exception as e:
                return ScannerResult(
                    scanner_name="trivy",
                    status="ERROR",
                    findings=findings,
                    error_message=f"Failed to execute Trivy: {str(e)}",
                    duration_seconds=time.time() - start_time,
                )

            stdout = proc.stdout.strip()
            if not stdout:
                continue

            try:
                data = json.loads(stdout)
                parsed = self._parse_trivy_report(data, target)
                findings.extend(parsed)
            except json.JSONDecodeError as err:
                logger.warning(f"Error parsing Trivy JSON for {target}: {err}")

        return ScannerResult(
            scanner_name="trivy",
            status="SUCCESS",
            findings=findings,
            duration_seconds=time.time() - start_time,
        )

    def _parse_trivy_report(self, data: dict, fallback_target: str) -> List[VulnerabilityFinding]:
        """Convert Trivy JSON report into normalized VulnerabilityFindings."""
        results: List[VulnerabilityFinding] = []
        report_results = data.get("Results", [])

        for res in report_results:
            target_name = res.get("Target") or fallback_target
            misconfigs = res.get("Misconfigurations", [])

            for item in misconfigs:
                rule_id = item.get("ID", "config-misconfiguration")
                title = item.get("Title", "Insecure Configuration")
                desc = item.get("Description") or item.get("Message", "")
                raw_severity = item.get("Severity", "LOW")
                severity = normalize_trivy_severity(raw_severity)

                cause = item.get("CauseMetadata", {})
                start_line = cause.get("StartLine")
                end_line = cause.get("EndLine", start_line)

                # Extract code line content if provided by Trivy
                snippet = None
                lines_info = cause.get("Code", {}).get("Lines", [])
                if lines_info:
                    line_contents = [ln.get("Content", "") for ln in lines_info if "Content" in ln]
                    if line_contents:
                        snippet = "\n".join(line_contents)

                resolution = item.get("Resolution", "")
                full_description = f"{desc}\nRecommended Fix: {resolution}" if resolution else desc

                finding = VulnerabilityFinding(
                    id=VulnerabilityFinding.generate_id("trivy", target_name, start_line, rule_id),
                    title=title,
                    category=VulnerabilityCategory.CONFIG,
                    severity=severity,
                    file_path=target_name,
                    line_number=start_line,
                    end_line_number=end_line,
                    code_snippet=snippet or resolution or "Misconfiguration detected in configuration file",
                    scanner="trivy",
                    rule_id=rule_id,
                    description=full_description,
                    ai_fix_available=True,
                )
                results.append(finding)

        return results

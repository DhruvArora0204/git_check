"""Severity classification and ranking for SecureCommit findings."""

from typing import Any, Dict, List
from securecommit.utils.config import SeverityLevel, VulnerabilityFinding


# Severity ordering priority (lower index = higher priority)
SEVERITY_ORDER: Dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
}


def normalize_semgrep_severity(raw_severity: str, rule_id: str, message: str) -> SeverityLevel:
    """Normalize Semgrep finding severity based on rule metadata and text."""
    raw = (raw_severity or "").upper()
    rule_lower = (rule_id or "").lower()
    msg_lower = (message or "").lower()

    # Remote code execution, command injection, deserialization, or hardcoded master keys
    critical_indicators = [
        "rce", "remote-code-execution", "command-injection", "insecure-deserialization",
        "cwe-78", "cwe-94", "cwe-502", "eval-injection", "code-injection"
    ]
    if any(ind in rule_lower or ind in msg_lower for ind in critical_indicators):
        return SeverityLevel.CRITICAL

    # SQL injection, authentication bypass, path traversal
    high_indicators = [
        "sql-injection", "sqli", "cwe-89", "auth-bypass", "path-traversal",
        "cwe-22", "ssrf", "cwe-918", "hardcoded-secret"
    ]
    if any(ind in rule_lower or ind in msg_lower for ind in high_indicators):
        return SeverityLevel.HIGH

    if raw == "ERROR":
        return SeverityLevel.HIGH
    elif raw == "WARNING":
        return SeverityLevel.MEDIUM
    elif raw == "INFO":
        return SeverityLevel.LOW

    return SeverityLevel.MEDIUM


def normalize_gitleaks_severity(rule_id: str, secret_type: str = "") -> SeverityLevel:
    """Normalize Gitleaks finding severity. Exposed secrets are inherently high/critical."""
    combined = f"{rule_id} {secret_type}".lower()
    critical_secrets = [
        "private-key", "rsa-private", "aws-secret", "gcp-service-account",
        "jwt-secret", "root-password", "master-key"
    ]
    if any(k in combined for k in critical_secrets):
        return SeverityLevel.CRITICAL
    return SeverityLevel.HIGH


def normalize_cvss_score(score: float) -> SeverityLevel:
    """Convert numeric CVSS score (0.0 - 10.0) into SeverityLevel."""
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    elif score >= 7.0:
        return SeverityLevel.HIGH
    elif score >= 4.0:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.LOW


def normalize_trivy_severity(raw_severity: str) -> SeverityLevel:
    """Normalize Trivy severity strings."""
    raw = (raw_severity or "").upper()
    if raw == "CRITICAL":
        return SeverityLevel.CRITICAL
    elif raw == "HIGH":
        return SeverityLevel.HIGH
    elif raw == "MEDIUM":
        return SeverityLevel.MEDIUM
    elif raw in ("LOW", "UNKNOWN"):
        return SeverityLevel.LOW
    return SeverityLevel.LOW


def sort_findings_by_severity(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """Sort vulnerabilities in descending order of severity (Critical -> High -> Medium -> Low)."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line_number or 0))

"""Configuration and data models for SecureCommit."""

from enum import Enum
import hashlib
import os
from pathlib import Path
import shutil
import sys
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity levels matching project specifications."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VulnerabilityCategory(str, Enum):
    """Categories of detected security issues."""
    SAST = "SAST"
    SECRET = "Secret"
    DEPENDENCY = "Dependency"
    CONFIG = "Configuration"
    CUSTOM = "Custom"


class VulnerabilityFinding(BaseModel):
    """Normalized vulnerability finding format across all scanners."""
    id: str = Field(..., description="Deterministic unique identifier for this finding")
    title: str = Field(..., description="Summary title of the vulnerability")
    category: VulnerabilityCategory = Field(..., description="Category of the finding")
    severity: SeverityLevel = Field(..., description="Severity level")
    file_path: str = Field(..., description="Path to the affected file")
    line_number: Optional[int] = Field(None, description="Starting line number")
    end_line_number: Optional[int] = Field(None, description="Ending line number")
    code_snippet: Optional[str] = Field(None, description="Vulnerable code snippet or evidence")
    scanner: str = Field(..., description="Scanner that detected the issue (semgrep, gitleaks, osv-scanner, trivy)")
    rule_id: str = Field(..., description="Rule ID, CWE, or CVE identifier")
    description: str = Field(..., description="Detailed description or scanner explanation")
    ai_fix_available: bool = Field(True, description="Whether this finding supports AI remediation")

    @classmethod
    def generate_id(cls, scanner: str, file_path: str, line: Optional[int], rule_id: str) -> str:
        """Generate a stable unique hash identifier."""
        raw = f"{scanner}:{Path(file_path).as_posix()}:{line or 0}:{rule_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


class ScannerResult(BaseModel):
    """Result of an individual scanner execution."""
    scanner_name: str
    status: str = "SUCCESS"  # SUCCESS, SKIPPED, ERROR
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


class ScanReport(BaseModel):
    """Consolidated report across all security scanners."""
    scanned_files_count: int = 0
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    security_score: int = 100
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scanner_results: List[ScannerResult] = Field(default_factory=list)


# Severity scoring weights as specified:
# Critical = 10, High = 7, Medium = 4, Low = 1
SEVERITY_WEIGHTS: Dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 10,
    SeverityLevel.HIGH: 7,
    SeverityLevel.MEDIUM: 4,
    SeverityLevel.LOW: 1,
}

# Scanner timeouts in seconds
SCANNER_TIMEOUT_SECONDS: int = 45


def get_augmented_env() -> Dict[str, str]:
    """Returns an environment dictionary containing common binary paths for Windows and POSIX."""
    env = os.environ.copy()
    current_path = env.get("PATH", "")
    additional_paths = []

    if sys.platform == "win32":
        user_appdata = os.environ.get("APPDATA", "")
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        user_profile = os.environ.get("USERPROFILE", "")

        # 1. Read permanent user PATH directly from Windows Registry
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                reg_path, _ = winreg.QueryValueEx(key, "Path")
                for entry in reg_path.split(";"):
                    expanded = os.path.expandvars(entry.strip())
                    if expanded and os.path.isdir(expanded) and expanded not in additional_paths:
                        additional_paths.append(expanded)
        except Exception:
            pass

        # 2. Python user scripts directories (dynamic + static fallback)
        try:
            import site
            user_site = site.getusersitepackages()
            scripts_dir = os.path.join(os.path.dirname(user_site), "Scripts")
            if os.path.isdir(scripts_dir) and scripts_dir not in additional_paths:
                additional_paths.append(scripts_dir)
            direct_scripts = os.path.join(user_site, "Scripts")
            if os.path.isdir(direct_scripts) and direct_scripts not in additional_paths:
                additional_paths.append(direct_scripts)
        except Exception:
            pass

        # Python install scripts directory
        py_scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
        if os.path.isdir(py_scripts) and py_scripts not in additional_paths:
            additional_paths.append(py_scripts)

        # 3. Known WinGet Package folders containing executables
        winget_pkg_root = os.path.join(local_appdata, "Microsoft", "WinGet", "Packages")
        if os.path.isdir(winget_pkg_root):
            try:
                for root, dirs, files in os.walk(winget_pkg_root):
                    if any(f.lower().endswith(".exe") for f in files):
                        if root not in additional_paths:
                            additional_paths.append(root)
            except Exception:
                pass

        candidate_paths = [
            os.path.join(user_appdata, "Python", "Python314", "Scripts"),
            os.path.join(user_appdata, "Python", "Python313", "Scripts"),
            os.path.join(user_appdata, "Python", "Python312", "Scripts"),
            os.path.join(user_appdata, "Python", "Python311", "Scripts"),
            os.path.join(local_appdata, "Microsoft", "WinGet", "Links"),
            os.path.join(local_appdata, "Microsoft", "WindowsApps"),
            os.path.join(user_profile, ".local", "osv-scanner"),
            os.path.join(user_profile, ".cargo", "bin"),
            os.path.join(user_profile, "go", "bin"),
        ]
        for cp in candidate_paths:
            if os.path.isdir(cp) and cp not in additional_paths:
                additional_paths.append(cp)
    else:
        home = os.path.expanduser("~")
        candidate_paths = [
            os.path.join(home, ".local", "bin"),
            "/usr/local/bin",
            "/opt/homebrew/bin",
            os.path.join(home, "go", "bin"),
        ]
        for cp in candidate_paths:
            if os.path.isdir(cp) and cp not in additional_paths:
                additional_paths.append(cp)

    if additional_paths:
        separator = ";" if sys.platform == "win32" else ":"
        env["PATH"] = separator.join(additional_paths) + separator + current_path

    return env


def find_executable(name: str) -> Optional[str]:
    """Locate an executable binary using augmented environment paths."""
    env = get_augmented_env()
    return shutil.which(name, path=env.get("PATH"))

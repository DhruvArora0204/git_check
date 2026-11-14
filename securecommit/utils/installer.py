"""Automated cross-platform downloader and installer for SecureCommit external scanner tools."""

import io
import logging
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tarfile
from typing import Callable, Dict, Optional
import urllib.request
import zipfile

from securecommit.utils.config import find_executable, get_augmented_env

logger = logging.getLogger(__name__)

SECURECOMMIT_HOME = Path.home() / ".securecommit"
BIN_DIR = SECURECOMMIT_HOME / "bin"

# Release URLs for automated installation across platforms
TOOL_DOWNLOAD_MATRIX = {
    "gitleaks": {
        "windows": {
            "AMD64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
            "x86_64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
            "ARM64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_arm64.zip",
        },
        "linux": {
            "x86_64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "AMD64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "aarch64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
        },
        "darwin": {
            "arm64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
            "x86_64": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
        },
    },
    "osv-scanner": {
        "windows": {
            "AMD64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_windows_amd64.exe",
            "x86_64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_windows_amd64.exe",
            "ARM64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_windows_arm64.exe",
        },
        "linux": {
            "x86_64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64",
            "AMD64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64",
            "aarch64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_arm64",
        },
        "darwin": {
            "arm64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_darwin_arm64",
            "x86_64": "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_darwin_amd64",
        },
    },
    "trivy": {
        "windows": {
            "AMD64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_windows-64bit.zip",
            "x86_64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_windows-64bit.zip",
            "ARM64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_windows-ARM64.zip",
        },
        "linux": {
            "x86_64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
            "AMD64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
            "aarch64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-ARM64.tar.gz",
        },
        "darwin": {
            "arm64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_macOS-ARM64.tar.gz",
            "x86_64": "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_macOS-64bit.tar.gz",
        },
    },
}


def get_system_key() -> str:
    """Detect normalized operating system key."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("darwin"):
        return "darwin"
    return "linux"


def get_arch_key() -> str:
    """Detect system architecture."""
    machine = platform.machine()
    if machine in ("AMD64", "x86_64", "amd64"):
        return "AMD64"
    if machine in ("arm64", "aarch64", "ARM64"):
        return "arm64" if sys.platform == "darwin" else "ARM64"
    return machine


def get_bin_dir() -> Path:
    """Get the target bin directory for SecureCommit binaries."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    return BIN_DIR


def add_bin_dir_to_user_path():
    """Ensure ~/.securecommit/bin is present in in-memory PATH and Windows user registry."""
    bin_path = str(get_bin_dir())
    current_path = os.environ.get("PATH", "")
    if bin_path not in current_path:
        os.environ["PATH"] = bin_path + os.pathsep + current_path

    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_ALL_ACCESS) as key:
                try:
                    reg_path, _ = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    reg_path = ""
                if bin_path.lower() not in reg_path.lower():
                    new_reg_path = f"{bin_path};{reg_path}" if reg_path else bin_path
                    winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_reg_path)
        except Exception as e:
            logger.debug(f"Could not persist bin dir to Windows Registry: {e}")


def get_download_url(tool_name: str) -> Optional[str]:
    """Retrieve the appropriate download URL for this platform and architecture."""
    system = get_system_key()
    arch = get_arch_key()

    tool_matrix = TOOL_DOWNLOAD_MATRIX.get(tool_name, {})
    sys_matrix = tool_matrix.get(system, {})

    # Match arch or fallback to first available
    if arch in sys_matrix:
        return sys_matrix[arch]
    if "AMD64" in sys_matrix:
        return sys_matrix["AMD64"]
    if "x86_64" in sys_matrix:
        return sys_matrix["x86_64"]
    return next(iter(sys_matrix.values()), None) if sys_matrix else None


def download_and_install_tool(tool_name: str, log_fn: Optional[Callable[[str], None]] = None) -> bool:
    """Download, extract, and install a standalone scanner binary into ~/.securecommit/bin."""
    def _log(msg: str):
        if log_fn:
            log_fn(msg)
        else:
            logger.info(msg)

    url = get_download_url(tool_name)
    if not url:
        _log(f"No binary download available for {tool_name} on {sys.platform}/{platform.machine()}")
        return False

    bin_dir = get_bin_dir()
    is_windows = sys.platform == "win32"
    exe_suffix = ".exe" if is_windows else ""
    target_exe_name = f"{tool_name}{exe_suffix}"
    target_path = bin_dir / target_exe_name

    _log(f"Downloading {tool_name} from {url}...")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecureCommit-Installer/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            content = response.read()

        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                # Find the main executable in the archive
                matching_members = [
                    m for m in z.namelist()
                    if m.lower().endswith(target_exe_name.lower()) or m.lower() == f"{tool_name}{exe_suffix}".lower()
                ]
                if not matching_members:
                    # Look for any file with matching name ignoring path
                    matching_members = [m for m in z.namelist() if Path(m).name.lower() == target_exe_name.lower()]

                if matching_members:
                    member_name = matching_members[0]
                    with z.open(member_name) as src, open(target_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                else:
                    _log(f"Could not locate {target_exe_name} inside the downloaded zip archive.")
                    return False

        elif url.endswith(".tar.gz") or url.endswith(".tgz"):
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as t:
                for member in t.getmembers():
                    if Path(member.name).name.lower() == target_exe_name.lower():
                        extracted_file = t.extractfile(member)
                        if extracted_file:
                            with open(target_path, "wb") as dst:
                                shutil.copyfileobj(extracted_file, dst)
                            break

        else:
            # Direct binary executable download (e.g. osv-scanner)
            with open(target_path, "wb") as dst:
                dst.write(content)

        # Ensure executable permissions on Unix
        if not is_windows and target_path.exists():
            target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        add_bin_dir_to_user_path()
        _log(f"Successfully installed {tool_name} to {target_path}")
        return True

    except Exception as e:
        _log(f"Failed to install {tool_name}: {e}")
        return False


def ensure_all_tools(verbose: bool = True, log_fn: Optional[Callable[[str], None]] = None) -> Dict[str, bool]:
    """
    Check all required external security scanners and automatically download any missing ones.

    Scanners handled:
      - gitleaks (Secret Detection)
      - osv-scanner (Dependency Scanner)
      - trivy (Config & Container Security)
      (Note: semgrep is installed via Python pip package dependencies)
    """
    def _log(msg: str):
        if log_fn:
            log_fn(msg)
        elif verbose:
            print(msg)

    add_bin_dir_to_user_path()

    tools_to_check = ["gitleaks", "osv-scanner", "trivy"]
    status: Dict[str, bool] = {}

    for tool in tools_to_check:
        loc = find_executable(tool)
        if loc:
            status[tool] = True
            if verbose:
                _log(f"[✓] {tool} is already installed at: {loc}")
        else:
            _log(f"[!] {tool} not found. Automatically downloading and installing...")
            success = download_and_install_tool(tool, log_fn=_log)
            status[tool] = success

    return status

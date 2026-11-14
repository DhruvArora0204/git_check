"""Git staged files detection and repository helper."""

import logging
from pathlib import Path
import subprocess
from typing import List, Optional
from securecommit.utils.config import get_augmented_env

logger = logging.getLogger(__name__)


def is_git_repository(repo_path: str = ".") -> bool:
    """Check if the path is inside a working Git repository tree."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            env=get_augmented_env(),
        )
        return res.returncode == 0 and res.stdout.strip() == "true"
    except Exception:
        return False


def get_git_root(repo_path: str = ".") -> Optional[Path]:
    """Retrieve absolute path to the Git repository root."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            env=get_augmented_env(),
        )
        if res.returncode == 0:
            return Path(res.stdout.strip()).resolve()
    except Exception as e:
        logger.warning(f"Failed to obtain git root: {e}")
    return None


def get_staged_files(repo_path: str = ".") -> List[str]:
    """
    Retrieve list of staged files ready for commit.
    Uses --diff-filter=ACMR to only include Added, Copied, Modified, or Renamed files.
    Deleted files are excluded since they no longer exist on disk.
    """
    if not is_git_repository(repo_path):
        return []

    git_root = get_git_root(repo_path)
    if not git_root:
        return []

    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=str(git_root),
            capture_output=True,
            text=True,
            env=get_augmented_env(),
        )
        if res.returncode != 0:
            return []

        relative_paths = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        absolute_existing_paths: List[str] = []

        for rel in relative_paths:
            full_path = (git_root / rel).resolve()
            if full_path.exists() and full_path.is_file():
                absolute_existing_paths.append(str(full_path))

        return absolute_existing_paths
    except Exception as e:
        logger.error(f"Error querying staged files: {e}")
        return []

"""Git pre-commit hook installation and interactive decision handler."""

import os
from pathlib import Path
import stat
import sys
import threading
from typing import List, Optional
from rich.console import Console
from rich.prompt import Prompt
from securecommit.cli import render_banner, render_scan_report
from securecommit.git.staged_files import get_git_root, get_staged_files, is_git_repository
from securecommit.scanner.analyzer import SecurityAnalyzer
from securecommit.utils.config import ScanReport, SeverityLevel

console = Console()

HOOK_TEMPLATE = """#!/bin/sh
# SecureCommit Pre-Commit Security Hook
# Automatically scans staged changes before committing.

# Re-direct to python runner
python -m securecommit.git.hooks
exit $?
"""


def show_popup_notification(title: str, message: str):
    """
    Display a supplementary popup notification where supported.
    Runs asynchronously so it never blocks the primary CLI interaction.
    """
    def _display():
        try:
            if sys.platform == "win32":
                import ctypes
                # 0x00000030 = MB_ICONWARNING | MB_OK
                ctypes.windll.user32.MessageBoxW(0, message, title, 0x00000030)
            else:
                import shutil
                if shutil.which("notify-send"):
                    os.system(f'notify-send "{title}" "{message}"')
        except Exception:
            pass

    thread = threading.Thread(target=_display, daemon=True)
    thread.start()


def install_hook(repo_path: str = ".") -> bool:
    """Install SecureCommit pre-commit hook into target Git repository."""
    git_root = get_git_root(repo_path)
    if not git_root:
        console.print("[bold red][Error][/bold red] Not a Git repository.")
        return False

    hooks_dir = git_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists():
        backup_file = hooks_dir / "pre-commit.securecommit.bak"
        if backup_file.exists():
            backup_file.unlink()
        hook_file.rename(backup_file)
        console.print(f"[yellow][!] Existing pre-commit hook backed up to {backup_file.name}[/yellow]")

    hook_file.write_text(HOOK_TEMPLATE, encoding="utf-8")

    # Set executable permissions
    try:
        current_mode = hook_file.stat().st_mode
        hook_file.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    console.print(f"[bold green][✓] SecureCommit pre-commit hook installed successfully at {hook_file}[/bold green]")
    return True


def uninstall_hook(repo_path: str = ".") -> bool:
    """Remove SecureCommit pre-commit hook."""
    git_root = get_git_root(repo_path)
    if not git_root:
        console.print("[bold red][Error][/bold red] Not a Git repository.")
        return False

    hook_file = git_root / ".git" / "hooks" / "pre-commit"
    if not hook_file.exists():
        console.print("[yellow][!] No pre-commit hook found.[/yellow]")
        return False

    hook_file.unlink()
    console.print("[bold green][✓] SecureCommit pre-commit hook uninstalled.[/bold green]")

    backup_file = git_root / ".git" / "hooks" / "pre-commit.securecommit.bak"
    if backup_file.exists():
        backup_file.rename(hook_file)
        console.print(f"[cyan][✓] Restored previous hook from backup: {backup_file.name}[/cyan]")

    return True


def prompt_developer_decision(report: ScanReport) -> int:
    """
    Present decision options to developer and handle input.
    Returns exit code (0 for commit to proceed, 1 to abort commit).
    """
    from securecommit.ai.remediation import AIRemediationEngine

    console.print("[bold]WHAT WOULD YOU LIKE TO DO?[/bold]")
    console.print()
    console.print("1. Review AI fixes and select issues to fix")
    console.print("2. Commit anyway without fixing")
    console.print("3. Abort commit")
    console.print()

    # Open TTY / Console directly to allow interactive input during git commit
    interactive_stdin = None
    try:
        if sys.platform == "win32":
            interactive_stdin = open("CONIN$", "r")
        else:
            interactive_stdin = open("/dev/tty", "r")
    except Exception:
        interactive_stdin = sys.stdin

    choice = ""
    while choice not in ("1", "2", "3"):
        try:
            sys.stdout.write("Select an option (1-3): ")
            sys.stdout.flush()
            choice = interactive_stdin.readline().strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Commit aborted by user interrupt.[/yellow]")
            return 1

    if choice == "1":
        engine = AIRemediationEngine()
        total_vulns = len(report.vulnerabilities)

        console.print("\n[bold cyan]=== SELECT VULNERABILITIES FOR AI REMEDIATION ===[/bold cyan]\n")
        for idx, v in enumerate(report.vulnerabilities, start=1):
            console.print(f"[{idx}] [bold]{v.title}[/bold] ({v.severity.value}) - {v.file_path}:{v.line_number or 'N/A'}")

        console.print("\nEnter comma-separated numbers to review (e.g. 1, 2), 'all', or 'q' to cancel:")
        sys.stdout.write("Selection: ")
        sys.stdout.flush()
        sel = interactive_stdin.readline().strip().lower()

        if sel == "q":
            console.print("[yellow]Remediation review cancelled. Committing aborted.[/yellow]")
            return 1

        selected_indices = []
        if sel == "all":
            selected_indices = list(range(total_vulns))
        else:
            for part in sel.split(","):
                part = part.strip()
                if part.isdigit() and 1 <= int(part) <= total_vulns:
                    selected_indices.append(int(part) - 1)

        if not selected_indices:
            console.print("[yellow]No valid vulnerabilities selected. Commit aborted.[/yellow]")
            return 1

        applied_count = 0
        for s_idx in selected_indices:
            vuln = report.vulnerabilities[s_idx]
            console.print(f"\n[bold cyan]Generating AI Remediation for: {vuln.title}...[/bold cyan]")
            advice = engine.generate_advice(vuln)

            # Render structured AI remediation advice
            console.print(f"\n[bold green]► Explanation:[/bold green] {advice.simple_explanation}")
            console.print(f"[bold yellow]► Risk Analysis:[/bold yellow] {advice.why_dangerous}")
            console.print(f"[bold red]► Exploit Scenario:[/bold red] {advice.exploit_scenario}")
            console.print("\n[bold]Current Code:[/bold]")
            console.print(f"   [dim]{vuln.code_snippet or 'N/A'}[/dim]")
            console.print("\n[bold green]Suggested Secure Implementation:[/bold green]")
            console.print(f"   [green]{advice.suggested_fix_code}[/green]")
            console.print(f"\n[bold cyan]► Justification:[/bold cyan] {advice.safety_justification}\n")

            # Ask developer approval
            sys.stdout.write(f"Apply this fix to '{vuln.file_path}'? (y/n): ")
            sys.stdout.flush()
            approve = interactive_stdin.readline().strip().lower()

            if approve in ("y", "yes"):
                success = engine.apply_approved_patch(
                    file_path=vuln.file_path,
                    original_snippet=vuln.code_snippet or "",
                    replacement_code=advice.suggested_fix_code,
                    stage_git=True,
                )
                if success:
                    console.print(f"[bold green][✓] Successfully applied and staged fix for {vuln.title}![/bold green]")
                    applied_count += 1
                else:
                    console.print(f"[bold yellow][!] Could not automatically replace snippet in {vuln.file_path}. Please update manually.[/bold yellow]")
            else:
                console.print(f"[dim][-] Fix skipped for {vuln.title}. Code unchanged.[/dim]")

        console.print(f"\n[bold]Remediation session complete. Applied {applied_count} fixes.[/bold]")
        console.print("1. Proceed with commit now")
        console.print("2. Abort commit to inspect files")
        sys.stdout.write("Select action (1-2): ")
        sys.stdout.flush()
        post_choice = interactive_stdin.readline().strip()

        if post_choice == "1":
            console.print("[bold green][✓] Proceeding with commit.[/bold green]")
            return 0
        else:
            console.print("[bold red][✗] Commit aborted. Changes remain staged for your review.[/bold red]")
            return 1

    elif choice == "2":
        console.print("[bold yellow][!] Committing anyway without fixing detected vulnerabilities.[/bold yellow]")
        return 0

    elif choice == "3":
        console.print("[bold red][✗] Commit aborted by developer. Staged changes preserved.[/bold red]")
        return 1

    return 1


def run_pre_commit_hook(show_popup: bool = True) -> int:
    """
    Main hook execution flow:
    1. Detect staged changes.
    2. Scan staged files.
    3. If clean: show success and proceed with exit code 0.
    4. If vulnerabilities found: display report, show supplementary popup, prompt developer.
    """
    render_banner()
    console.print("[bold]Scanning staged changes...[/bold]\n")

    staged_files = get_staged_files()
    if not staged_files:
        console.print("[dim]No staged files detected to scan.[/dim]")
        return 0

    analyzer = SecurityAnalyzer()
    report = analyzer.scan_files(staged_files)

    # Render clean scan or vulnerability report
    render_scan_report(report)

    if not report.vulnerabilities:
        console.print("[bold green][✓] Commit successful.[/bold green]")
        return 0

    # Vulnerabilities found: trigger supplementary popup if enabled
    if show_popup:
        popup_msg = (
            f"SecureCommit detected {len(report.vulnerabilities)} vulnerabilities!\n"
            f"Security Score: {report.security_score}/100\n"
            f"Critical: {report.critical_count}, High: {report.high_count}\n\n"
            f"Please respond in the terminal to proceed or abort."
        )
        show_popup_notification("SecureCommit Security Alert", popup_msg)

    # Prompt developer for decision
    return prompt_developer_decision(report)


if __name__ == "__main__":
    exit_code = run_pre_commit_hook()
    sys.exit(exit_code)

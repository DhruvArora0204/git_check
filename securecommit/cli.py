"""Command Line Interface for SecureCommit using Typer and Rich."""

from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer
from securecommit.reports.scoring import format_scoring_explanation
from securecommit.scanner.analyzer import SecurityAnalyzer
from securecommit.utils.config import ScanReport, SeverityLevel

console = Console()
app = typer.Typer(
    name="securecommit",
    help="AI-Powered, IDE-Independent Code Vulnerability Detection & Remediation Tool",
    add_completion=False,
)


def render_banner():
    """Render SecureCommit header banner."""
    title_text = Text("SECURECOMMIT", style="bold cyan")
    sub_text = Text("AI-Powered Pre-Commit Security Engine", style="dim")
    console.print(title_text)
    console.print(sub_text)
    console.print()


def render_scan_report(report: ScanReport):
    """Render comprehensive scan report matching project CLI specifications."""
    console.print(f"[bold]Files scanned:[/bold] {report.scanned_files_count}")
    console.print(f"[bold]Vulnerabilities found:[/bold] {len(report.vulnerabilities)}")
    console.print()

    # Score color coding
    if report.security_score >= 85:
        score_style = "bold green"
    elif report.security_score >= 60:
        score_style = "bold yellow"
    else:
        score_style = "bold red"

    console.print(f"[bold]Security Score:[/bold] [{score_style}]{report.security_score}/100[/{score_style}]")
    console.print()

    console.print(f"[bold red]Critical:[/bold red] {report.critical_count}")
    console.print(f"[bold color(208)]High:[/bold color(208)]     {report.high_count}")
    console.print(f"[bold yellow]Medium:[/bold yellow]   {report.medium_count}")
    console.print(f"[bold blue]Low:[/bold blue]      {report.low_count}")
    console.print()

    # Display scanner status alerts if any failed or were skipped
    warnings = [r for r in report.scanner_results if r.status in ("SKIPPED", "ERROR")]
    if warnings:
        for w in warnings:
            color = "yellow" if w.status == "SKIPPED" else "red"
            console.print(f"[{color}][!] {w.scanner_name.upper()} ({w.status}): {w.error_message}[/{color}]")
        console.print()

    # Clean Scan
    if not report.vulnerabilities:
        if not warnings:
            console.print("[bold green][✓] Security scan completed.[/bold green]")
            console.print(f"[bold green][✓] {report.scanned_files_count} files scanned.[/bold green]")
            console.print("[bold green][✓] No vulnerabilities detected.[/bold green]")
            console.print()
            console.print("[bold cyan]Your project looks clean![/bold cyan]")
        else:
            console.print("[bold yellow][!] No vulnerabilities detected in executed scanners, but some scanners were skipped or encountered errors above.[/bold yellow]")
        return

    # List Detected Vulnerabilities in descending severity order
    console.print("[bold]DETECTED VULNERABILITIES[/bold]")
    console.print()

    for idx, vuln in enumerate(report.vulnerabilities, start=1):
        # Severity color styling
        if vuln.severity == SeverityLevel.CRITICAL:
            sev_badge = "[bold white on red] Critical [/bold white on red]"
        elif vuln.severity == SeverityLevel.HIGH:
            sev_badge = "[bold white on color(202)] High [/bold white on color(202)]"
        elif vuln.severity == SeverityLevel.MEDIUM:
            sev_badge = "[bold black on yellow] Medium [/bold black on yellow]"
        else:
            sev_badge = "[bold white on blue] Low [/bold white on blue]"

        console.print(f"[bold]{idx}. {vuln.title}[/bold]")
        console.print(f"   Severity: {sev_badge}")
        console.print(f"   Category: {vuln.category.value} ({vuln.scanner})")
        console.print(f"   File:     {vuln.file_path}")
        if vuln.line_number:
            console.print(f"   Line:     {vuln.line_number}")
        if vuln.rule_id:
            console.print(f"   Rule:     {vuln.rule_id}")
        if vuln.ai_fix_available:
            console.print("   AI Fix:   [green]Available[/green]")
        if vuln.code_snippet:
            clean_snippet = vuln.code_snippet.strip().splitlines()[:3]
            formatted_snippet = "\n      ".join(clean_snippet)
            console.print(f"   Snippet:  [dim]{formatted_snippet}[/dim]")
        console.print()


@app.command()
def fix(
    paths: Optional[List[str]] = typer.Argument(None, help="Specific files to scan and remediate"),
    dir: str = typer.Option(".", "--dir", "-d", help="Directory to scan if no files specified"),
):
    """Scan files and interactively review and apply AI-powered vulnerability fixes."""
    render_banner()
    from securecommit.ai.remediation import AIRemediationEngine
    from securecommit.git.staged_files import get_staged_files

    analyzer = SecurityAnalyzer()
    if paths:
        targets = paths
    else:
        staged = get_staged_files()
        if staged:
            console.print(f"[dim]Scanning {len(staged)} staged files...[/dim]\n")
            targets = staged
        else:
            console.print(f"[dim]Scanning directory {Path(dir).resolve()}...[/dim]\n")
            report = analyzer.scan_directory(dir)
            targets = None

    if targets is not None:
        report = analyzer.scan_files(targets)

    render_scan_report(report)

    if not report.vulnerabilities:
        console.print("[bold green]No issues to remediate![/bold green]")
        raise typer.Exit(code=0)

    engine = AIRemediationEngine()
    console.print(f"[bold cyan]Starting AI Remediation for {len(report.vulnerabilities)} detected issues...[/bold cyan]\n")

    for idx, vuln in enumerate(report.vulnerabilities, start=1):
        console.print(f"\n[bold]{idx}/{len(report.vulnerabilities)}. {vuln.title}[/bold] ({vuln.severity.value}) - {vuln.file_path}:{vuln.line_number or 'N/A'}")
        advice = engine.generate_advice(vuln)
        console.print(f"\n[bold green]► Explanation:[/bold green] {advice.simple_explanation}")
        console.print(f"[bold yellow]► Risk Analysis:[/bold yellow] {advice.why_dangerous}")
        console.print(f"[bold red]► Exploit Scenario:[/bold red] {advice.exploit_scenario}")
        console.print("\n[bold]Current Code:[/bold]")
        console.print(f"   [dim]{vuln.code_snippet or 'N/A'}[/dim]")
        console.print("\n[bold green]Suggested Secure Implementation:[/bold green]")
        console.print(f"   [green]{advice.suggested_fix_code}[/green]")
        console.print(f"\n[bold cyan]► Justification:[/bold cyan] {advice.safety_justification}\n")

        apply_fix = typer.confirm(f"Apply this fix to '{vuln.file_path}'?", default=False)
        if apply_fix:
            success = engine.apply_approved_patch(
                file_path=vuln.file_path,
                original_snippet=vuln.code_snippet or "",
                replacement_code=advice.suggested_fix_code,
                stage_git=True,
            )
            if success:
                console.print(f"[bold green][✓] Applied and staged fix for {vuln.title}![/bold green]")
            else:
                console.print(f"[bold yellow][!] Could not auto-apply snippet. Please review manually.[/bold yellow]")
        else:
            console.print("[dim][-] Skipped.[/dim]")

    console.print("\n[bold green][✓] Remediation review finished.[/bold green]")


@app.command()
def scan(
    paths: Optional[List[str]] = typer.Argument(None, help="Target files or directories to scan"),
    dir: str = typer.Option(".", "--dir", "-d", help="Directory to scan if no files specified"),
    rules: Optional[str] = typer.Option(None, "--rules", "-r", help="Path to custom Semgrep rules file"),
    explain_score: bool = typer.Option(False, "--explain-score", help="Print transparent score breakdown"),
):
    """Execute a vulnerability scan across target files or directories."""
    render_banner()

    analyzer = SecurityAnalyzer(custom_rule_path=rules)

    if paths:
        console.print(f"Scanning target files ({len(paths)} specified)...")
        console.print()
        report = analyzer.scan_files(paths)
    else:
        console.print(f"Scanning directory: {Path(dir).resolve()}...")
        console.print()
        report = analyzer.scan_directory(dir)

    render_scan_report(report)

    if explain_score:
        console.print()
        console.print(Panel(format_scoring_explanation(report.security_score, {
            SeverityLevel.CRITICAL: report.critical_count,
            SeverityLevel.HIGH: report.high_count,
            SeverityLevel.MEDIUM: report.medium_count,
            SeverityLevel.LOW: report.low_count,
        }), title="Scoring Explanation", border_style="cyan"))

    if report.vulnerabilities:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def install_hook(repo: str = typer.Option(".", "--repo", "-r", help="Git repository root path")):
    """Install SecureCommit Git pre-commit hook into a repository."""
    render_banner()
    from securecommit.git.hooks import install_hook as do_install
    success = do_install(repo)
    if not success:
        raise typer.Exit(code=1)


@app.command()
def uninstall_hook(repo: str = typer.Option(".", "--repo", "-r", help="Git repository root path")):
    """Uninstall SecureCommit Git pre-commit hook from a repository."""
    render_banner()
    from securecommit.git.hooks import uninstall_hook as do_uninstall
    success = do_uninstall(repo)
    if not success:
        raise typer.Exit(code=1)


@app.command()
def scan_staged(
    rules: Optional[str] = typer.Option(None, "--rules", "-r", help="Path to custom Semgrep rules file"),
    explain_score: bool = typer.Option(False, "--explain-score", help="Print transparent score breakdown"),
):
    """Scan only currently staged Git files without running the full commit hook."""
    render_banner()
    from securecommit.git.staged_files import get_staged_files

    staged = get_staged_files()
    if not staged:
        console.print("[dim]No staged files detected in the current Git repository.[/dim]")
        raise typer.Exit(code=0)

    console.print(f"Scanning staged files ({len(staged)} staged)...")
    console.print()
    analyzer = SecurityAnalyzer(custom_rule_path=rules)
    report = analyzer.scan_files(staged)
    render_scan_report(report)

    if explain_score:
        console.print()
        console.print(Panel(format_scoring_explanation(report.security_score, {
            SeverityLevel.CRITICAL: report.critical_count,
            SeverityLevel.HIGH: report.high_count,
            SeverityLevel.MEDIUM: report.medium_count,
            SeverityLevel.LOW: report.low_count,
        }), title="Scoring Explanation", border_style="cyan"))

    if report.vulnerabilities:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="hook", hidden=True)
def run_hook_command():
    """Internal command executed by Git pre-commit hook."""
    from securecommit.git.hooks import run_pre_commit_hook
    code = run_pre_commit_hook()
    raise typer.Exit(code=code)


@app.command()
def check_tools():
    """Verify installation and status of integrated security tools."""
    render_banner()
    console.print("[bold]Checking integrated scanner tools availability...[/bold]\n")

    analyzer = SecurityAnalyzer()
    table = Table(title="Scanner Tools Status")
    table.add_column("Scanner", style="bold")
    table.add_column("Purpose")
    table.add_column("Status")
    table.add_column("Location / Remediation")

    tools = [
        ("Semgrep", "Static Code Analysis (SAST)", analyzer.semgrep_scanner.is_available(), analyzer.semgrep_scanner.executable or "Install: pip install semgrep"),
        ("Gitleaks", "Secret & Credential Detection", analyzer.secret_scanner.is_available(), analyzer.secret_scanner.executable or "Install: winget install Gitleaks.Gitleaks"),
        ("OSV-Scanner", "Dependency Vulnerability Scanner", analyzer.dependency_scanner.is_available(), analyzer.dependency_scanner.executable or "Install: winget install Google.OSVScanner"),
        ("Trivy", "Config & Container Security", analyzer.config_scanner.is_available(), analyzer.config_scanner.executable or "Install: winget install AquaSecurity.Trivy"),
    ]

    for name, purpose, is_avail, loc in tools:
        status_text = "[green]AVAILABLE[/green]" if is_avail else "[red]NOT FOUND[/red]"
        table.add_row(name, purpose, status_text, str(loc))

    console.print(table)


def main():
    app()


if __name__ == "__main__":
    main()

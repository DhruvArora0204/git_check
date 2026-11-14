# SecureCommit Automated Setup Script for Windows PowerShell
# Installs SecureCommit, tools, updates PATH, and installs the Git pre-commit hook.

$ErrorActionPreference = 'Continue'

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "       SecureCommit Setup Engine        " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. Update User PATH with Python Scripts directory
Write-Host "`n[1/4] Configuring Python Scripts PATH..." -ForegroundColor Yellow
$pythonScripts = python -c "import site, os; print(os.path.join(os.path.dirname(site.getusersitepackages()), 'Scripts'))" 2>$null
if (-not $pythonScripts -or -not (Test-Path $pythonScripts)) {
    $pythonScripts = "$env:APPDATA\Python\Python314\Scripts"
}

if (Test-Path $pythonScripts) {
    if ($env:Path -notlike "*$pythonScripts*") {
        $env:Path = "$pythonScripts;$env:Path"
    }
    $userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($userPath -notlike "*$pythonScripts*") {
        [Environment]::SetEnvironmentVariable("Path", "$pythonScripts;$userPath", [EnvironmentVariableTarget]::User)
        Write-Host "  -> Added '$pythonScripts' to permanent User PATH." -ForegroundColor Green
    } else {
        Write-Host "  -> Python Scripts already in permanent User PATH." -ForegroundColor Gray
    }
}

# 2. Check and Install Scanners via WinGet
Write-Host "`n[2/4] Verifying security scanner binaries..." -ForegroundColor Yellow
$packages = @(
    @{ Id = "Gitleaks.Gitleaks"; Name = "Gitleaks" },
    @{ Id = "AquaSecurity.Trivy"; Name = "Trivy" },
    @{ Id = "Google.OSVScanner"; Name = "OSV-Scanner" }
)

foreach ($pkg in $packages) {
    $check = winget list --id $pkg.Id 2>$null | Select-String $pkg.Id
    if (-not $check) {
        Write-Host "  -> Installing $($pkg.Name) via WinGet..." -ForegroundColor Cyan
        winget install --id $pkg.Id --silent --accept-source-agreements --accept-package-agreements
    } else {
        Write-Host "  -> $($pkg.Name) is already installed." -ForegroundColor Green
    }
}

# 3. Verify Scanner Integration
Write-Host "`n[3/4] Verifying SecureCommit scanner discovery..." -ForegroundColor Yellow
python -m securecommit check-tools

# 4. Install Git Pre-Commit Hook in Current Repository (if inside git repo)
Write-Host "`n[4/4] Setting up Git pre-commit hook..." -ForegroundColor Yellow
$isGit = git rev-parse --is-inside-work-tree 2>$null
if ($isGit -eq "true") {
    python -m securecommit install-hook
    Write-Host "  -> SecureCommit pre-commit hook installed in current repository." -ForegroundColor Green
} else {
    Write-Host "  -> Current folder is not a Git repository." -ForegroundColor Gray
    Write-Host "  -> Whenever you are in a Git repo, simply run: python -m securecommit install-hook" -ForegroundColor Cyan
}

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "       Setup Completed Successfully!     " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "You can now run: 'securecommit' or 'python -m securecommit'" -ForegroundColor White

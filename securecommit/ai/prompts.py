"""Prompt templates and data schemas for AI-powered vulnerability remediation."""

from typing import Optional
from pydantic import BaseModel, Field
from securecommit.utils.config import VulnerabilityFinding


class RemediationAdvice(BaseModel):
    """Structured remediation response from AI model."""
    vulnerability_id: str
    simple_explanation: str = Field(..., description="Simple, clear explanation of what is wrong")
    why_dangerous: str = Field(..., description="Why the detected code is potentially dangerous")
    exploit_scenario: str = Field(..., description="How an attacker could exploit this vulnerability")
    suggested_fix_code: str = Field(..., description="Suggested secure code implementation")
    safety_justification: str = Field(..., description="Why the suggested code is safer and solves the issue")
    original_snippet: Optional[str] = Field(None, description="Original code block to replace")


SYSTEM_PROMPT = """You are SecureCommit AI, an elite cybersecurity engineer and application security specialist.
Your role is to analyze verified security findings reported by security scanners, explain the security risks to the developer, and suggest precise, production-grade secure code implementations.

Guidelines:
1. Always generate practical, idiomatic, and syntactically valid code fixes.
2. For SQL Injection: provide parameterized queries or prepared statements.
3. For Command Injection: use subprocess with list arguments (shell=False) or safe native APIs.
4. For XSS: apply contextual output encoding or templates with autoescaping.
5. For Insecure Deserialization: replace pickle/eval with safe data interchange formats (JSON, SafeLoader).
6. For Weak Cryptography: upgrade to SHA-256 or bcrypt/argon2.
7. For Hardcoded Secrets: recommend loading from environment variables (os.environ, .env).
8. For Container/Config issues: provide secure directive configurations (e.g. non-root USER, HEALTHCHECK).
9. Output your response strictly formatted as valid JSON matching the required schema.
"""


def build_remediation_prompt(finding: VulnerabilityFinding, file_context: Optional[str] = None) -> str:
    """Build structured user prompt containing sanitized vulnerability details."""
    context_str = f"\nFile Context (around line {finding.line_number}):\n```\n{file_context}\n```\n" if file_context else ""

    return f"""Please provide an explanation and secure remediation for the following security vulnerability:

Vulnerability Title: {finding.title}
Category: {finding.category.value}
Severity: {finding.severity.value}
Scanner: {finding.scanner}
Rule / CWE / ID: {finding.rule_id}
File: {finding.file_path}
Line: {finding.line_number or 'N/A'}
Scanner Explanation: {finding.description}

Detected Vulnerable Code Snippet:
```
{finding.code_snippet or 'N/A'}
```{context_str}

Respond strictly with a JSON object containing the following keys:
- "simple_explanation": "Concise plain-English explanation of the vulnerability"
- "why_dangerous": "Detailed explanation of why this code pattern is dangerous"
- "exploit_scenario": "Realistic example of how an attacker might exploit this"
- "suggested_fix_code": "The drop-in replacement secure code snippet"
- "safety_justification": "Why this specific fix prevents exploitation"
"""

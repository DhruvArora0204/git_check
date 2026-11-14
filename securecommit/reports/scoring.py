"""Security score calculation based on detected vulnerability severities."""

from typing import Dict, List, Tuple
from securecommit.utils.config import SEVERITY_WEIGHTS, SeverityLevel, VulnerabilityFinding


def calculate_security_score(findings: List[VulnerabilityFinding]) -> Tuple[int, Dict[SeverityLevel, int]]:
    """
    Calculate overall repository security score out of 100 and count per severity level.

    Scoring formula:
        Penalty = (Critical * 10) + (High * 7) + (Medium * 4) + (Low * 1)
        Security Score = max(0, 100 - Penalty)

    A clean scan receives a score of 100.
    """
    counts: Dict[SeverityLevel, int] = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 0,
        SeverityLevel.MEDIUM: 0,
        SeverityLevel.LOW: 0,
    }

    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    penalty = sum(counts[sev] * SEVERITY_WEIGHTS[sev] for sev in SeverityLevel)
    score = max(0, 100 - penalty)

    return score, counts


def format_scoring_explanation(score: int, counts: Dict[SeverityLevel, int]) -> str:
    """Generate a transparent explanation of the score calculation."""
    crit = counts.get(SeverityLevel.CRITICAL, 0)
    high = counts.get(SeverityLevel.HIGH, 0)
    med = counts.get(SeverityLevel.MEDIUM, 0)
    low = counts.get(SeverityLevel.LOW, 0)

    deduction = (crit * 10) + (high * 7) + (med * 4) + (low * 1)
    return (
        f"Base Score: 100\n"
        f"Penalties: Critical ({crit} x 10 = {crit * 10}) + "
        f"High ({high} x 7 = {high * 7}) + "
        f"Medium ({med} x 4 = {med * 4}) + "
        f"Low ({low} x 1 = {low * 1}) = -{deduction}\n"
        f"Final Security Score: {score}/100"
    )

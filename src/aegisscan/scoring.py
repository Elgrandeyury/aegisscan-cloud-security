from __future__ import annotations

from .models import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 0,
}


def risk_score(findings: list[Finding]) -> int:
    """Return a security score from 0-100, where 100 is best."""
    penalty = sum(SEVERITY_WEIGHTS.get(finding.severity.upper(), 0) for finding in findings)
    return max(0, 100 - penalty)


def risk_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"

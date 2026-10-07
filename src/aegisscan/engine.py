from __future__ import annotations

import re
from pathlib import Path

from .config import ScanConfig
from .models import Finding
from .rules import scan_kubernetes, scan_terraform

SUPPORTED_SUFFIXES = {".tf", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".terraform", ".venv", "venv", "node_modules", "dist", "build"}
SEVERITY_RANKS = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SUPPRESSION_RE = re.compile(r"aegisscan:ignore\s+([A-Za-z0-9-]+)", re.IGNORECASE)


def scan_path(target: Path, config: ScanConfig | None = None) -> tuple[list[Finding], int]:
    config = config or ScanConfig()
    findings: list[Finding] = []
    files_scanned = 0
    root = target if target.is_dir() else target.parent

    for path in _iter_files(target):
        if config.is_path_ignored(path, root):
            continue

        text = _read_text(path)
        if text is None:
            continue
        files_scanned += 1

        if path.suffix == ".tf":
            file_findings = scan_terraform(path, text)
        elif path.suffix in {".yaml", ".yml"}:
            file_findings = scan_kubernetes(path, text)
        else:
            file_findings = []

        suppressed = _suppressed_rules(text)
        findings.extend(
            finding
            for finding in file_findings
            if finding.rule_id.upper() not in config.disabled_rules
            and finding.rule_id.upper() not in suppressed
            and _meets_minimum_severity(finding.severity, config.minimum_severity)
        )

    findings.sort(key=lambda item: (_severity_rank(item.severity), item.rule_id, item.file))
    return findings, files_scanned


def _iter_files(target: Path):
    if target.is_file():
        if target.suffix.lower() in SUPPORTED_SUFFIXES:
            yield target
        return

    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SUPPORTED_SUFFIXES:
            yield path


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _suppressed_rules(text: str) -> set[str]:
    return {match.group(1).upper() for match in SUPPRESSION_RE.finditer(text)}


def _meets_minimum_severity(severity: str, minimum: str) -> bool:
    minimum_key = minimum.upper()
    if minimum_key not in SEVERITY_RANKS:
        minimum_key = "LOW"
    return SEVERITY_RANKS.get(severity.upper(), 99) <= SEVERITY_RANKS[minimum_key]


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANKS.get(severity.upper(), 9)

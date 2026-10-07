from __future__ import annotations

from pathlib import Path

from .models import Finding
from .rules import scan_kubernetes, scan_terraform

SUPPORTED_SUFFIXES = {".tf", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".terraform", ".venv", "venv", "node_modules", "dist", "build"}


def scan_path(target: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files_scanned = 0

    for path in _iter_files(target):
        text = _read_text(path)
        if text is None:
            continue
        files_scanned += 1

        if path.suffix == ".tf":
            findings.extend(scan_terraform(path, text))
        elif path.suffix in {".yaml", ".yml"}:
            findings.extend(scan_kubernetes(path, text))

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


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 9)

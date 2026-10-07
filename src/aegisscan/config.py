from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml


@dataclass
class ScanConfig:
    disabled_rules: set[str] = field(default_factory=set)
    ignored_paths: list[str] = field(default_factory=list)
    fail_on: str | None = None
    minimum_severity: str = "low"

    def is_path_ignored(self, path: Path, root: Path) -> bool:
        try:
            relative = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            relative = path.as_posix()
        return any(fnmatch(relative, pattern) for pattern in self.ignored_paths)


def load_config(root: Path, explicit: Path | None = None) -> ScanConfig:
    config_path = explicit or _find_config(root)
    if config_path is None or not config_path.exists():
        return ScanConfig()

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    scan = raw.get("scan", {})
    rules = raw.get("rules", {})
    ci = raw.get("ci", {})

    return ScanConfig(
        disabled_rules={str(item).upper() for item in rules.get("disabled", [])},
        ignored_paths=[str(item) for item in scan.get("ignore_paths", [])],
        fail_on=ci.get("fail_on"),
        minimum_severity=str(scan.get("minimum_severity", "low")).lower(),
    )


def _find_config(root: Path) -> Path | None:
    start = root if root.is_dir() else root.parent
    candidate = start / ".aegisscan.yml"
    if candidate.exists():
        return candidate
    candidate = start / ".aegisscan.yaml"
    return candidate if candidate.exists() else None

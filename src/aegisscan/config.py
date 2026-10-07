from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml

from .errors import ConfigurationError

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_FAIL_ON = VALID_SEVERITIES | {"none"}


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
    if config_path is None:
        return ScanConfig()
    if not config_path.exists() or not config_path.is_file():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not read configuration: {config_path}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("Configuration root must be a YAML mapping.")

    scan = _mapping(raw.get("scan", {}), "scan")
    rules = _mapping(raw.get("rules", {}), "rules")
    ci = _mapping(raw.get("ci", {}), "ci")

    ignored_paths = _string_list(scan.get("ignore_paths", []), "scan.ignore_paths")
    disabled_rules = _string_list(rules.get("disabled", []), "rules.disabled")

    minimum_severity = str(scan.get("minimum_severity", "low")).lower()
    if minimum_severity not in VALID_SEVERITIES:
        raise ConfigurationError(
            "scan.minimum_severity must be one of: " + ", ".join(sorted(VALID_SEVERITIES))
        )

    raw_fail_on = ci.get("fail_on")
    fail_on = None if raw_fail_on is None else str(raw_fail_on).lower()
    if fail_on is not None and fail_on not in VALID_FAIL_ON:
        raise ConfigurationError("ci.fail_on must be one of: " + ", ".join(sorted(VALID_FAIL_ON)))

    return ScanConfig(
        disabled_rules={item.upper() for item in disabled_rules},
        ignored_paths=ignored_paths,
        fail_on=fail_on,
        minimum_severity=minimum_severity,
    )


def _mapping(value: object, key: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{key} must be a YAML mapping.")
    return value


def _string_list(value: object, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{key} must be a list of strings.")
    return value


def _find_config(root: Path) -> Path | None:
    start = root if root.is_dir() else root.parent
    candidate = start / ".aegisscan.yml"
    if candidate.exists():
        return candidate
    candidate = start / ".aegisscan.yaml"
    return candidate if candidate.exists() else None

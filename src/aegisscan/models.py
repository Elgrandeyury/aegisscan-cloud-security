from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int | None
    message: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanTarget:
    path: Path
    kind: str

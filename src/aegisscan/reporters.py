from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Finding

console = Console()


def render_terminal(findings: list[Finding], files_scanned: int) -> None:
    console.print("[bold cyan]AegisScan[/bold cyan] [dim]Cloud & IaC Security Scanner[/dim]")
    console.print(f"Scanned [bold]{files_scanned}[/bold] supported files. Findings: [bold]{len(findings)}[/bold]\n")

    if not findings:
        console.print("[bold green]No findings detected by the enabled AegisScan rules.[/bold green]")
        return

    table = Table(show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Finding")
    table.add_column("Location")

    for finding in findings:
        location = finding.file if finding.line is None else f"{finding.file}:{finding.line}"
        table.add_row(finding.severity, finding.rule_id, finding.title, location)

    console.print(table)

    for finding in findings:
        console.print(f"\n[bold]{finding.rule_id} — {finding.title}[/bold]")
        console.print(f"{finding.message}")
        console.print(f"[dim]Remediation:[/dim] {finding.remediation}")


def write_json(findings: list[Finding], files_scanned: int, output: Path) -> None:
    payload = {
        "tool": "AegisScan",
        "files_scanned": files_scanned,
        "summary": _summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _summary(findings: list[Finding]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = finding.severity.lower()
        summary[key] = summary.get(key, 0) + 1
    return summary

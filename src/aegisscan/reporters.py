from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import Finding
from .scoring import risk_grade, risk_score

console = Console()


def render_terminal(findings: list[Finding], files_scanned: int) -> None:
    score = risk_score(findings)
    grade = risk_grade(score)
    console.print("[bold cyan]AegisScan[/bold cyan] [dim]Cloud & IaC Security Scanner[/dim]")
    console.print(
        f"Scanned [bold]{files_scanned}[/bold] supported files. "
        f"Findings: [bold]{len(findings)}[/bold]  "
        f"Security score: [bold]{score}/100 ({grade})[/bold]\n"
    )

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
        console.print(finding.message)
        console.print(f"[dim]Remediation:[/dim] {finding.remediation}")


def write_json(findings: list[Finding], files_scanned: int, output: Path) -> None:
    payload = _base_payload(findings, files_scanned)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_html(findings: list[Finding], files_scanned: int, output: Path) -> None:
    score = risk_score(findings)
    grade = risk_grade(score)
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(f.severity)}</td>"
        f"<td>{html.escape(f.rule_id)}</td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.file)}{':' + str(f.line) if f.line else ''}</td>"
        f"<td>{html.escape(f.remediation)}</td>"
        "</tr>"
        for f in findings
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisScan Security Report</title>
<style>
body{{font-family:Inter,Arial,sans-serif;margin:40px;background:#0b1020;color:#e8eefc}}
.card{{background:#121a2d;border:1px solid #24304a;border-radius:14px;padding:20px;margin-bottom:20px}}
h1{{margin-top:0}} .score{{font-size:32px;font-weight:700}} table{{width:100%;border-collapse:collapse}}
th,td{{padding:12px;border-bottom:1px solid #2a3652;text-align:left;vertical-align:top}}
th{{color:#9fb3d9}} code{{color:#8dd3ff}} .muted{{color:#9fb3d9}}
</style>
</head>
<body>
<div class="card"><h1>AegisScan</h1><div class="muted">Cloud & IaC Security Scanner</div>
<p class="score">{score}/100 — Grade {grade}</p>
<p>{files_scanned} files scanned · {len(findings)} findings</p></div>
<div class="card"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5">No findings detected.</td></tr>'}</tbody></table></div>
</body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")


def write_sarif(findings: list[Finding], output: Path) -> None:
    unique_rules: dict[str, Finding] = {}
    for finding in findings:
        unique_rules.setdefault(finding.rule_id, finding)

    rules = [
        {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation},
            "properties": {"security-severity": str(_sarif_security_score(finding.severity))},
        }
        for finding in unique_rules.values()
    ]
    results = []
    for finding in findings:
        region = {"startLine": finding.line} if finding.line else None
        physical = {"artifactLocation": {"uri": finding.file}}
        if region:
            physical["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": f"{finding.message} Remediation: {finding.remediation}"},
                "locations": [{"physicalLocation": physical}],
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AegisScan", "informationUri": "https://github.com/Elgrandeyury/aegisscan-cloud-security", "rules": rules}},
                "results": results,
            }
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _base_payload(findings: list[Finding], files_scanned: int) -> dict:
    score = risk_score(findings)
    return {
        "tool": "AegisScan",
        "files_scanned": files_scanned,
        "security_score": score,
        "grade": risk_grade(score),
        "summary": _summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def _summary(findings: list[Finding]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = finding.severity.lower()
        summary[key] = summary.get(key, 0) + 1
    return summary


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(severity.upper(), "warning")


def _sarif_security_score(severity: str) -> float:
    return {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5, "INFO": 0.0}.get(severity.upper(), 5.0)

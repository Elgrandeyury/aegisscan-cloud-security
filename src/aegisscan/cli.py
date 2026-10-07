from __future__ import annotations

from pathlib import Path

import typer

from . import __version__
from .engine import scan_path
from .reporters import render_terminal, write_json

app = typer.Typer(add_completion=False, help="AegisScan - Cloud & IaC Security Scanner")


@app.command()
def scan(
    target: Path = typer.Argument(Path("."), exists=True, readable=True, help="File or directory to scan."),
    json_output: Path | None = typer.Option(None, "--json", help="Write findings to a JSON report."),
    fail_on: str = typer.Option("high", help="Exit non-zero at or above: critical, high, medium, low, none."),
) -> None:
    """Scan Terraform and Kubernetes configuration for security misconfigurations."""
    findings, files_scanned = scan_path(target.resolve())
    render_terminal(findings, files_scanned)

    if json_output:
        write_json(findings, files_scanned, json_output)
        typer.echo(f"JSON report written to {json_output}")

    threshold = fail_on.lower()
    allowed = {"critical", "high", "medium", "low", "none"}
    if threshold not in allowed:
        raise typer.BadParameter(f"fail-on must be one of: {', '.join(sorted(allowed))}")

    if threshold != "none" and _should_fail(findings, threshold):
        raise typer.Exit(code=2)


@app.command("rules")
def list_rules() -> None:
    """List built-in AegisScan rule identifiers."""
    rules = [
        ("AEGIS-AWS-001", "HIGH", "Public ingress exposure"),
        ("AEGIS-AWS-002", "CRITICAL", "Public S3 bucket ACL"),
        ("AEGIS-AWS-003", "CRITICAL", "Publicly accessible database"),
        ("AEGIS-AWS-004", "MEDIUM", "EBS encryption not explicitly enabled"),
        ("AEGIS-AWS-005", "HIGH", "Wildcard IAM action"),
        ("AEGIS-K8S-001", "MEDIUM", "Externally exposed LoadBalancer service"),
        ("AEGIS-K8S-002", "CRITICAL", "Privileged container"),
        ("AEGIS-K8S-003", "HIGH", "Privilege escalation not disabled"),
        ("AEGIS-K8S-004", "MEDIUM", "Missing resource requests or limits"),
        ("AEGIS-K8S-005", "MEDIUM", "Mutable container image tag"),
    ]
    for rule_id, severity, title in rules:
        typer.echo(f"{rule_id:<15} {severity:<8} {title}")


@app.command()
def version() -> None:
    """Print the AegisScan version."""
    typer.echo(f"AegisScan {__version__}")


def _should_fail(findings, threshold: str) -> bool:
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    limit = ranks[threshold]
    return any(ranks.get(finding.severity.lower(), 99) <= limit for finding in findings)


if __name__ == "__main__":
    app()

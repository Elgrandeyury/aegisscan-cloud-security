from __future__ import annotations

from pathlib import Path

import typer

from . import __version__
from .config import load_config
from .engine import scan_path
from .reporters import render_terminal, write_html, write_json, write_sarif
from .rules import RULE_CATALOG

app = typer.Typer(add_completion=False, help="AegisScan - Cloud & IaC Security Scanner")


@app.command()
def scan(
    target: Path = typer.Argument(Path("."), exists=True, readable=True, help="File or directory to scan."),
    config_path: Path | None = typer.Option(None, "--config", help="Path to .aegisscan.yml."),
    json_output: Path | None = typer.Option(None, "--json", help="Write findings to a JSON report."),
    html_output: Path | None = typer.Option(None, "--html", help="Write a branded HTML security report."),
    sarif_output: Path | None = typer.Option(None, "--sarif", help="Write SARIF for GitHub Code Scanning."),
    fail_on: str | None = typer.Option(None, help="Exit non-zero at or above: critical, high, medium, low, none."),
) -> None:
    """Scan Terraform and Kubernetes configuration for security misconfigurations."""
    resolved = target.resolve()
    config = load_config(resolved, config_path)
    findings, files_scanned = scan_path(resolved, config=config)
    render_terminal(findings, files_scanned)

    if json_output:
        write_json(findings, files_scanned, json_output)
        typer.echo(f"JSON report written to {json_output}")
    if html_output:
        write_html(findings, files_scanned, html_output)
        typer.echo(f"HTML report written to {html_output}")
    if sarif_output:
        write_sarif(findings, sarif_output)
        typer.echo(f"SARIF report written to {sarif_output}")

    threshold = (fail_on or config.fail_on or "high").lower()
    allowed = {"critical", "high", "medium", "low", "none"}
    if threshold not in allowed:
        raise typer.BadParameter(f"fail-on must be one of: {', '.join(sorted(allowed))}")

    if threshold != "none" and _should_fail(findings, threshold):
        raise typer.Exit(code=2)


@app.command("rules")
def list_rules() -> None:
    """List built-in AegisScan rule identifiers."""
    for rule_id, severity, title in RULE_CATALOG:
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

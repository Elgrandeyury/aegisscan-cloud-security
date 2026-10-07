# AegisScan

**AegisScan** is a Python CLI security scanner for Terraform and Kubernetes configuration. It detects cloud and workload misconfigurations before they reach production using its own first-party rule engine and Aegis rule IDs.

```bash
aegisscan scan .
```

## Current capabilities

AegisScan currently supports:

- Terraform (`.tf`) scanning
- Kubernetes YAML (`.yaml`, `.yml`) scanning
- custom Aegis rule IDs
- severity-based findings
- remediation guidance
- project security score (`0-100`) and grade (`A-F`)
- JSON reports
- branded HTML reports
- SARIF output for GitHub Code Scanning
- `.aegisscan.yml` configuration
- path exclusions
- rule disabling
- minimum severity filtering
- file-level rule suppression
- CI security gates with `--fail-on`

## Current rules

| Rule | Severity | Check |
| --- | --- | --- |
| `AEGIS-AWS-001` | High | Public ingress from `0.0.0.0/0` |
| `AEGIS-AWS-002` | Critical | Public S3 ACL |
| `AEGIS-AWS-003` | Critical | Publicly accessible RDS |
| `AEGIS-AWS-004` | Medium | EBS encryption not explicitly enabled |
| `AEGIS-AWS-005` | High | Wildcard IAM actions |
| `AEGIS-K8S-001` | Medium | LoadBalancer service exposure |
| `AEGIS-K8S-002` | Critical | Privileged container |
| `AEGIS-K8S-003` | High | Privilege escalation not disabled |
| `AEGIS-K8S-004` | Medium | Missing CPU/memory requests or limits |
| `AEGIS-K8S-005` | Medium | Mutable or unpinned container image |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Usage

```bash
# Scan current directory
aegisscan scan .

# Scan a specific infrastructure directory
aegisscan scan ./terraform

# Generate reports
aegisscan scan . --json reports/aegisscan.json
aegisscan scan . --html reports/aegisscan.html
aegisscan scan . --sarif reports/aegisscan.sarif

# CI security gate
aegisscan scan . --fail-on high

# Use a specific configuration file
aegisscan scan . --config .aegisscan.yml

# List built-in rules
aegisscan rules
```

## Configuration

Copy `.aegisscan.yml.example` to `.aegisscan.yml` and customize it:

```yaml
scan:
  minimum_severity: low
  ignore_paths:
    - "examples/**"
    - "vendor/**"

rules:
  disabled:
    - AEGIS-K8S-001

ci:
  fail_on: high
```

A rule can also be intentionally suppressed for a file:

```text
# aegisscan:ignore AEGIS-AWS-001
```

Suppressions should be used only when the risk is understood and accepted.

## Security score

AegisScan calculates a simple risk-weighted score from `0-100`, where `100` means no enabled AegisScan findings were detected. Critical and high-severity findings reduce the score more heavily than medium and low findings.

Example:

```text
AegisScan Cloud & IaC Security Scanner
Scanned 8 supported files. Findings: 3  Security score: 57/100 (F)
```

The score is a prioritization aid, not a compliance certification.

## Reports

**JSON** is intended for automation and downstream processing.

**HTML** provides a recruiter/team-friendly security report with the project score, findings, locations, and remediation guidance.

**SARIF** allows AegisScan results to be consumed by compatible code-scanning systems such as GitHub Code Scanning workflows.

## Repository structure

```text
src/aegisscan/
├── cli.py          # CLI commands and CI exit behavior
├── config.py       # .aegisscan.yml configuration
├── engine.py       # file discovery, filtering, suppression, orchestration
├── models.py       # finding models
├── reporters.py    # terminal, JSON, HTML and SARIF reporting
├── rules.py        # first-party AegisScan detection rules
└── scoring.py      # risk score and grade calculation

tests/              # rule, configuration and engine tests
examples/vulnerable # intentionally insecure IaC samples
.github/workflows/  # CI validation
```

## Design principles

AegisScan is intentionally being developed as its own security tool rather than a wrapper around Checkov, Trivy, or another scanner. The goal is to keep the detection logic understandable, testable, extensible, and suitable for DevSecOps workflows.

## Project status

**Product foundation implemented.** Configuration, exclusions, rule suppressions, security scoring, JSON/HTML/SARIF reporting, CI gating, initial AWS/Kubernetes rules, vulnerable examples, tests, and packaging are in place.

Next development focus: stronger structured Terraform analysis, a larger AWS/Kubernetes rule library, per-rule documentation, additional false-positive tests, and tighter GitHub Code Scanning integration.

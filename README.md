# AegisScan

**AegisScan** is a Python CLI security scanner for Terraform and Kubernetes configuration. It is designed to detect common cloud and workload misconfigurations before they reach production.

```bash
aegisscan scan .
```

## What it scans

AegisScan currently inspects:

- Terraform (`.tf`)
- Kubernetes YAML (`.yaml`, `.yml`)

The scanner uses its own rule engine and Aegis rule IDs rather than wrapping another security scanner.

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

Scan the current directory:

```bash
aegisscan scan .
```

Scan a specific infrastructure directory:

```bash
aegisscan scan ./terraform
```

Generate a JSON report:

```bash
aegisscan scan . --json aegisscan-report.json
```

Use it as a CI security gate:

```bash
aegisscan scan . --fail-on high
```

List rules:

```bash
aegisscan rules
```

## Example output

```text
AegisScan Cloud & IaC Security Scanner
Scanned 2 supported files. Findings: 7

CRITICAL  AEGIS-AWS-003   Publicly accessible database
CRITICAL  AEGIS-K8S-002  Privileged container
HIGH      AEGIS-AWS-001   Public ingress exposure
HIGH      AEGIS-AWS-005   Wildcard IAM action
...
```

## Repository structure

```text
src/aegisscan/
├── cli.py          # CLI commands
├── engine.py       # file discovery and scan orchestration
├── models.py       # finding models
├── reporters.py    # terminal and JSON reporting
└── rules.py        # AegisScan detection rules

tests/              # rule tests
examples/vulnerable # intentionally insecure IaC samples
.github/workflows/  # CI validation
```

## Design goals

AegisScan is being built as a standalone security tool with:

- custom rule identifiers
- severity-based findings
- actionable remediation guidance
- machine-readable output
- CI-friendly exit codes
- Terraform and Kubernetes support
- extensible rule architecture

## Project status

**v0.1 foundation implemented.** The CLI, first-party scan engine, initial AWS/Kubernetes rule set, JSON reporting, vulnerable examples, automated tests, and CI workflow are in place. More parsers, rules, configuration, SARIF/HTML reporting, and suppression controls are planned.

# AegisScan

**AegisScan** is a Python CLI security scanner for Terraform and Kubernetes configuration. It detects cloud and workload misconfigurations before they reach production using its own first-party rule engine and stable Aegis rule IDs.

```bash
aegisscan scan .
```

## AegisScan v0.2

AegisScan currently includes:

- structured Terraform HCL parsing
- Kubernetes YAML parsing
- 31 built-in AWS and Kubernetes security rules
- custom Aegis rule IDs
- Critical / High / Medium / Low severity levels
- actionable remediation guidance
- project security score (`0-100`) and grade (`A-F`)
- JSON reports
- branded HTML reports
- SARIF output for GitHub Code Scanning
- `.aegisscan.yml` configuration
- path exclusions
- disabled-rule configuration
- minimum-severity filtering
- file-level suppressions
- CI security gates with `--fail-on`
- vulnerable and hardened example configurations
- automated linting, tests, CLI validation, and clean-example verification in GitHub Actions

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
# Scan the current project
aegisscan scan .

# Scan one infrastructure directory
aegisscan scan ./terraform

# Generate reports
aegisscan scan . --json reports/aegisscan.json
aegisscan scan . --html reports/aegisscan.html
aegisscan scan . --sarif reports/aegisscan.sarif

# Fail CI when High or Critical findings exist
aegisscan scan . --fail-on high

# Use a project configuration file
aegisscan scan . --config .aegisscan.yml

# List built-in rules
aegisscan rules

# Show version
aegisscan version
```

## Configuration

Copy `.aegisscan.yml.example` to `.aegisscan.yml`:

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

A reviewed finding can also be suppressed at file level:

```text
# aegisscan:ignore AEGIS-AWS-001
```

Suppressions should represent deliberate risk acceptance, not a way to hide unresolved findings.

## Rule coverage

AegisScan v0.2 ships with **31 rules**:

- **14 AWS / Terraform rules** covering public exposure, IAM wildcard permissions, S3 controls, RDS/EBS/EFS encryption, CloudTrail, KMS, EC2 public IPs, IMDSv2, and root-volume encryption.
- **17 Kubernetes rules** covering public service exposure, privileged workloads, privilege escalation, root execution, writable root filesystems, Linux capabilities, host namespaces, hostPath, service-account tokens, seccomp, probes, resources, mutable images, and NodePort.

See [`docs/rules.md`](docs/rules.md) for the full rule reference and remediation guidance.

## Security score

AegisScan calculates a simple risk-weighted score from `0-100`. Critical and High findings reduce the score more heavily than Medium and Low findings.

```text
AegisScan Cloud & IaC Security Scanner
Scanned 8 supported files. Findings: 3  Security score: 57/100 (F)
```

The score is a prioritization aid, not a compliance certification.

## Reports

**JSON** is intended for automation and downstream processing.

**HTML** provides a readable security report with score, findings, locations, and remediation guidance.

**SARIF** allows AegisScan findings to be consumed by compatible code-scanning systems such as GitHub Code Scanning.

## Repository structure

```text
src/aegisscan/
├── cli.py          # CLI commands and CI exit behavior
├── config.py       # .aegisscan.yml configuration
├── engine.py       # discovery, filtering, suppressions, orchestration
├── models.py       # finding models
├── reporters.py    # terminal, JSON, HTML and SARIF output
├── rules.py        # first-party Terraform/Kubernetes detection rules
└── scoring.py      # risk score and grade calculation

docs/
└── rules.md        # rule reference and remediation guidance

examples/
├── vulnerable/     # intentionally insecure fixtures
└── secure/         # hardened fixtures expected to scan clean

tests/              # rule and engine tests
.github/workflows/  # automated CI validation
```

## Design principles

AegisScan is intentionally built as its own security tool rather than as a wrapper around Checkov, Trivy, or another scanner. The goal is to keep detection logic understandable, testable, extensible, and suitable for DevSecOps workflows.

## Project status

**v0.2 product milestone implemented.**

The repository now contains the CLI, structured Terraform and Kubernetes scanning, 31 first-party rules, configuration and suppressions, scoring, JSON/HTML/SARIF reporting, hardened and vulnerable fixtures, automated tests, and CI validation.

Future work can focus on additional cloud providers, deeper expression evaluation, policy packs, package publishing, and broader real-world fixture coverage rather than basic project scaffolding.

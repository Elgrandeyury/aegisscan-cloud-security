# Changelog

## 0.2.0 — 2026-10-07

### Added
- 31 first-party security rules across AWS Terraform and Kubernetes.
- Structured Terraform parsing with `python-hcl2`.
- Kubernetes YAML scanning.
- `.aegisscan.yml` configuration, ignored paths, disabled rules, and severity filtering.
- File-level `aegisscan:ignore RULE-ID` suppressions.
- Security score and A-F grade.
- JSON, HTML, and SARIF reports.
- CI failure thresholds through `--fail-on`.
- Vulnerable and hardened example configurations.
- Automated lint, tests, CLI checks, and hardened-example verification.
- Real CI integrations with the AWS Terraform and Kubernetes flagship repositories.

### Hardened
- Findings now use exit code `1`; scanner/configuration errors use exit code `2`.
- Configuration values are validated before scanning.
- Removed license metadata that had not been explicitly selected for the project.

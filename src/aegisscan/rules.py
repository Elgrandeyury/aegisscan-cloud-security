from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import yaml

from .models import Finding


OPEN_CIDR = "0.0.0.0/0"


def scan_terraform(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []

    if 'cidr_blocks' in text and OPEN_CIDR in text:
        findings.append(
            Finding(
                rule_id="AEGIS-AWS-001",
                title="Public ingress exposure",
                severity="HIGH",
                category="Network",
                file=str(path),
                line=_line_of(text, OPEN_CIDR),
                message="Terraform allows ingress from 0.0.0.0/0.",
                remediation="Restrict ingress to trusted CIDR ranges or reference another security group.",
            )
        )

    if re.search(r'(?s)resource\s+"aws_s3_bucket".*?public-read', text):
        findings.append(
            Finding(
                rule_id="AEGIS-AWS-002",
                title="Public S3 bucket ACL",
                severity="CRITICAL",
                category="Storage",
                file=str(path),
                line=_line_of(text, "public-read"),
                message="S3 configuration appears to allow public-read access.",
                remediation="Use private ACLs and S3 Block Public Access controls.",
            )
        )

    if 'aws_db_instance' in text and re.search(r'publicly_accessible\s*=\s*true', text):
        findings.append(
            Finding(
                rule_id="AEGIS-AWS-003",
                title="Publicly accessible database",
                severity="CRITICAL",
                category="Database",
                file=str(path),
                line=_line_of(text, "publicly_accessible"),
                message="RDS is configured as publicly accessible.",
                remediation="Place the database in private subnets and set publicly_accessible = false.",
            )
        )

    if 'aws_ebs_volume' in text and not re.search(r'encrypted\s*=\s*true', text):
        findings.append(
            Finding(
                rule_id="AEGIS-AWS-004",
                title="EBS encryption not explicitly enabled",
                severity="MEDIUM",
                category="Encryption",
                file=str(path),
                line=_line_of(text, "aws_ebs_volume"),
                message="An EBS volume resource does not explicitly enable encryption.",
                remediation="Set encrypted = true and use an appropriate KMS key where required.",
            )
        )

    if re.search(r'(?s)action\s*=\s*\[?\s*"\*"', text):
        findings.append(
            Finding(
                rule_id="AEGIS-AWS-005",
                title="Wildcard IAM action",
                severity="HIGH",
                category="IAM",
                file=str(path),
                line=_line_of(text, '"*"'),
                message="IAM policy appears to grant wildcard actions.",
                remediation="Replace wildcard permissions with the minimum required actions.",
            )
        )

    return findings


def scan_kubernetes(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        docs: Iterable[object] = yaml.safe_load_all(text)
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            _scan_k8s_document(path, doc, findings)
    except yaml.YAMLError:
        return findings
    return findings


def _scan_k8s_document(path: Path, doc: dict, findings: list[Finding]) -> None:
    kind = str(doc.get("kind", ""))
    spec = doc.get("spec") or {}

    if kind == "Service" and spec.get("type") == "LoadBalancer":
        findings.append(
            Finding(
                rule_id="AEGIS-K8S-001",
                title="Externally exposed LoadBalancer service",
                severity="MEDIUM",
                category="Network",
                file=str(path),
                line=None,
                message="Service type LoadBalancer may expose the workload publicly.",
                remediation="Confirm public exposure is intended or use ClusterIP with a controlled ingress layer.",
            )
        )

    pod_spec = _pod_spec(doc)
    if not pod_spec:
        return

    for container in pod_spec.get("containers", []) or []:
        security = container.get("securityContext") or {}
        name = container.get("name", "container")

        if security.get("privileged") is True:
            findings.append(
                Finding(
                    rule_id="AEGIS-K8S-002",
                    title="Privileged container",
                    severity="CRITICAL",
                    category="Workload",
                    file=str(path),
                    line=None,
                    message=f"Container '{name}' runs in privileged mode.",
                    remediation="Remove privileged mode and grant only the Linux capabilities the workload requires.",
                )
            )

        if security.get("allowPrivilegeEscalation") is not False:
            findings.append(
                Finding(
                    rule_id="AEGIS-K8S-003",
                    title="Privilege escalation not disabled",
                    severity="HIGH",
                    category="Workload",
                    file=str(path),
                    line=None,
                    message=f"Container '{name}' does not explicitly disable privilege escalation.",
                    remediation="Set securityContext.allowPrivilegeEscalation: false.",
                )
            )

        resources = container.get("resources") or {}
        if not resources.get("requests") or not resources.get("limits"):
            findings.append(
                Finding(
                    rule_id="AEGIS-K8S-004",
                    title="Missing resource requests or limits",
                    severity="MEDIUM",
                    category="Reliability",
                    file=str(path),
                    line=None,
                    message=f"Container '{name}' is missing resource requests or limits.",
                    remediation="Define CPU and memory requests and limits for predictable scheduling and containment.",
                )
            )

        image = str(container.get("image", ""))
        if image.endswith(":latest") or ":" not in image:
            findings.append(
                Finding(
                    rule_id="AEGIS-K8S-005",
                    title="Mutable container image tag",
                    severity="MEDIUM",
                    category="Supply Chain",
                    file=str(path),
                    line=None,
                    message=f"Container '{name}' uses a mutable or unpinned image tag.",
                    remediation="Pin deployments to an immutable version tag or image digest.",
                )
            )


def _pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        return ((spec.get("template") or {}).get("spec") or {})
    if kind == "CronJob":
        return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})
    return None


def _line_of(text: str, token: str) -> int | None:
    for index, line in enumerate(text.splitlines(), start=1):
        if token in line:
            return index
    return None

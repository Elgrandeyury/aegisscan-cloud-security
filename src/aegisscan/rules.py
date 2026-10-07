from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import hcl2
import yaml

from .models import Finding

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

RULE_CATALOG = [
    ("AEGIS-AWS-001", "HIGH", "Public security-group ingress"),
    ("AEGIS-AWS-002", "CRITICAL", "Public S3 bucket ACL"),
    ("AEGIS-AWS-003", "CRITICAL", "Publicly accessible database"),
    ("AEGIS-AWS-004", "MEDIUM", "EBS encryption not enabled"),
    ("AEGIS-AWS-005", "HIGH", "Wildcard IAM action"),
    ("AEGIS-AWS-006", "HIGH", "S3 public access block weakened"),
    ("AEGIS-AWS-007", "HIGH", "RDS storage encryption not enabled"),
    ("AEGIS-AWS-008", "MEDIUM", "EFS encryption not enabled"),
    ("AEGIS-AWS-009", "MEDIUM", "CloudTrail log validation disabled"),
    ("AEGIS-AWS-010", "MEDIUM", "CloudTrail is not multi-region"),
    ("AEGIS-AWS-011", "MEDIUM", "KMS automatic key rotation disabled"),
    ("AEGIS-AWS-012", "HIGH", "EC2 public IP association enabled"),
    ("AEGIS-AWS-013", "HIGH", "EC2 IMDSv2 not enforced"),
    ("AEGIS-AWS-014", "MEDIUM", "EC2 root volume encryption not enabled"),
    ("AEGIS-K8S-001", "MEDIUM", "Externally exposed LoadBalancer service"),
    ("AEGIS-K8S-002", "CRITICAL", "Privileged container"),
    ("AEGIS-K8S-003", "HIGH", "Privilege escalation not disabled"),
    ("AEGIS-K8S-004", "MEDIUM", "Missing resource requests or limits"),
    ("AEGIS-K8S-005", "MEDIUM", "Mutable container image tag"),
    ("AEGIS-K8S-006", "HIGH", "Container may run as root"),
    ("AEGIS-K8S-007", "MEDIUM", "Writable root filesystem"),
    ("AEGIS-K8S-008", "MEDIUM", "Linux capabilities not fully dropped"),
    ("AEGIS-K8S-009", "HIGH", "Host network namespace enabled"),
    ("AEGIS-K8S-010", "HIGH", "Host PID namespace enabled"),
    ("AEGIS-K8S-011", "HIGH", "Host IPC namespace enabled"),
    ("AEGIS-K8S-012", "HIGH", "HostPath volume mounted"),
    ("AEGIS-K8S-013", "MEDIUM", "Service account token auto-mounted"),
    ("AEGIS-K8S-014", "MEDIUM", "Seccomp profile not configured"),
    ("AEGIS-K8S-015", "LOW", "Missing readiness probe"),
    ("AEGIS-K8S-016", "LOW", "Missing liveness probe"),
    ("AEGIS-K8S-017", "MEDIUM", "NodePort service exposure"),
]


def scan_terraform(path: Path, text: str) -> list[Finding]:
    try:
        parsed = hcl2.loads(text)
    except Exception:
        return []

    findings: list[Finding] = []
    for resource_type, name, attrs in _iter_tf_resources(parsed):
        line = _resource_line(text, resource_type, name)

        if resource_type in {"aws_security_group", "aws_security_group_rule"}:
            if _has_public_ingress(resource_type, attrs):
                findings.append(
                    _finding(
                        "AEGIS-AWS-001",
                        "Public security-group ingress",
                        "HIGH",
                        "Network",
                        path,
                        line,
                        "Ingress allows traffic from a public internet CIDR.",
                        "Restrict ingress to trusted CIDRs or security-group references.",
                    )
                )

        if resource_type in {"aws_s3_bucket", "aws_s3_bucket_acl"}:
            acl = str(attrs.get("acl", "")).lower()
            if acl in {"public-read", "public-read-write", "authenticated-read"}:
                findings.append(
                    _finding(
                        "AEGIS-AWS-002",
                        "Public S3 bucket ACL",
                        "CRITICAL",
                        "Storage",
                        path,
                        line,
                        f"S3 ACL is configured as '{acl}'.",
                        "Use private ACLs and enforce S3 Block Public Access.",
                    )
                )

        if resource_type == "aws_db_instance":
            if attrs.get("publicly_accessible") is True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-003",
                        "Publicly accessible database",
                        "CRITICAL",
                        "Database",
                        path,
                        line,
                        "RDS is configured as publicly accessible.",
                        "Use private subnets and set publicly_accessible = false.",
                    )
                )
            if attrs.get("storage_encrypted") is not True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-007",
                        "RDS storage encryption not enabled",
                        "HIGH",
                        "Encryption",
                        path,
                        line,
                        "RDS storage encryption is not explicitly enabled.",
                        "Set storage_encrypted = true and use an approved KMS key if required.",
                    )
                )

        if resource_type == "aws_ebs_volume" and attrs.get("encrypted") is not True:
            findings.append(
                _finding(
                    "AEGIS-AWS-004",
                    "EBS encryption not enabled",
                    "MEDIUM",
                    "Encryption",
                    path,
                    line,
                    "An EBS volume does not explicitly enable encryption.",
                    "Set encrypted = true and use an appropriate KMS key where required.",
                )
            )

        if resource_type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}:
            if _contains_wildcard_action(attrs):
                findings.append(
                    _finding(
                        "AEGIS-AWS-005",
                        "Wildcard IAM action",
                        "HIGH",
                        "IAM",
                        path,
                        line,
                        "IAM policy content appears to grant wildcard actions.",
                        "Replace wildcard actions with the minimum required permissions.",
                    )
                )

        if resource_type == "aws_iam_policy_document" and _contains_wildcard_action(attrs):
            findings.append(
                _finding(
                    "AEGIS-AWS-005",
                    "Wildcard IAM action",
                    "HIGH",
                    "IAM",
                    path,
                    line,
                    "IAM policy document grants wildcard actions.",
                    "Replace wildcard actions with the minimum required permissions.",
                )
            )

        if resource_type == "aws_s3_bucket_public_access_block":
            required = {
                "block_public_acls",
                "ignore_public_acls",
                "block_public_policy",
                "restrict_public_buckets",
            }
            if any(attrs.get(key) is not True for key in required):
                findings.append(
                    _finding(
                        "AEGIS-AWS-006",
                        "S3 public access block weakened",
                        "HIGH",
                        "Storage",
                        path,
                        line,
                        "One or more S3 Block Public Access controls are not enabled.",
                        "Enable all four S3 Block Public Access settings unless explicitly justified.",
                    )
                )

        if resource_type == "aws_efs_file_system" and attrs.get("encrypted") is not True:
            findings.append(
                _finding(
                    "AEGIS-AWS-008",
                    "EFS encryption not enabled",
                    "MEDIUM",
                    "Encryption",
                    path,
                    line,
                    "EFS encryption at rest is not explicitly enabled.",
                    "Set encrypted = true and select a KMS key where required.",
                )
            )

        if resource_type == "aws_cloudtrail":
            if attrs.get("enable_log_file_validation") is not True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-009",
                        "CloudTrail log validation disabled",
                        "MEDIUM",
                        "Logging",
                        path,
                        line,
                        "CloudTrail log file validation is not enabled.",
                        "Set enable_log_file_validation = true.",
                    )
                )
            if attrs.get("is_multi_region_trail") is not True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-010",
                        "CloudTrail is not multi-region",
                        "MEDIUM",
                        "Logging",
                        path,
                        line,
                        "CloudTrail is not explicitly configured as a multi-region trail.",
                        "Set is_multi_region_trail = true for broader audit coverage.",
                    )
                )

        if resource_type == "aws_kms_key" and attrs.get("enable_key_rotation") is not True:
            findings.append(
                _finding(
                    "AEGIS-AWS-011",
                    "KMS automatic key rotation disabled",
                    "MEDIUM",
                    "Encryption",
                    path,
                    line,
                    "KMS automatic key rotation is not explicitly enabled.",
                    "Set enable_key_rotation = true where automatic rotation is supported.",
                )
            )

        if resource_type == "aws_instance":
            if attrs.get("associate_public_ip_address") is True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-012",
                        "EC2 public IP association enabled",
                        "HIGH",
                        "Network",
                        path,
                        line,
                        "EC2 is configured to receive a public IP address.",
                        "Prefer private subnets and controlled ingress through a load balancer or bastion.",
                    )
                )

            metadata = _first_block(attrs.get("metadata_options"))
            if metadata.get("http_tokens") != "required":
                findings.append(
                    _finding(
                        "AEGIS-AWS-013",
                        "EC2 IMDSv2 not enforced",
                        "HIGH",
                        "Compute",
                        path,
                        line,
                        "EC2 metadata options do not enforce IMDSv2 tokens.",
                        "Set metadata_options.http_tokens = \"required\".",
                    )
                )

            root = _first_block(attrs.get("root_block_device"))
            if root and root.get("encrypted") is not True:
                findings.append(
                    _finding(
                        "AEGIS-AWS-014",
                        "EC2 root volume encryption not enabled",
                        "MEDIUM",
                        "Encryption",
                        path,
                        line,
                        "EC2 root block device encryption is not explicitly enabled.",
                        "Set root_block_device.encrypted = true.",
                    )
                )

    return findings


def scan_kubernetes(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        docs: Iterable[object] = yaml.safe_load_all(text)
        for doc in docs:
            if isinstance(doc, dict):
                _scan_k8s_document(path, doc, findings)
    except yaml.YAMLError:
        return findings
    return findings


def _scan_k8s_document(path: Path, doc: dict, findings: list[Finding]) -> None:
    kind = str(doc.get("kind", ""))
    spec = doc.get("spec") or {}

    if kind == "Service":
        if spec.get("type") == "LoadBalancer":
            findings.append(
                _finding(
                    "AEGIS-K8S-001",
                    "Externally exposed LoadBalancer service",
                    "MEDIUM",
                    "Network",
                    path,
                    None,
                    "Service type LoadBalancer may expose the workload publicly.",
                    "Confirm public exposure is intended or use a controlled ingress layer.",
                )
            )
        if spec.get("type") == "NodePort":
            findings.append(
                _finding(
                    "AEGIS-K8S-017",
                    "NodePort service exposure",
                    "MEDIUM",
                    "Network",
                    path,
                    None,
                    "NodePort exposes the service on every eligible node interface.",
                    "Prefer ClusterIP with an ingress/load balancer unless NodePort is required.",
                )
            )

    pod_spec = _pod_spec(doc)
    if not pod_spec:
        return

    if pod_spec.get("hostNetwork") is True:
        findings.append(_k8s_flag(path, "AEGIS-K8S-009", "Host network namespace enabled", "hostNetwork"))
    if pod_spec.get("hostPID") is True:
        findings.append(_k8s_flag(path, "AEGIS-K8S-010", "Host PID namespace enabled", "hostPID"))
    if pod_spec.get("hostIPC") is True:
        findings.append(_k8s_flag(path, "AEGIS-K8S-011", "Host IPC namespace enabled", "hostIPC"))

    for volume in pod_spec.get("volumes", []) or []:
        if isinstance(volume, dict) and "hostPath" in volume:
            findings.append(
                _finding(
                    "AEGIS-K8S-012",
                    "HostPath volume mounted",
                    "HIGH",
                    "Workload",
                    path,
                    None,
                    f"Volume '{volume.get('name', 'volume')}' mounts a hostPath.",
                    "Avoid hostPath or strictly scope it to a justified, read-only path.",
                )
            )

    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(
            _finding(
                "AEGIS-K8S-013",
                "Service account token auto-mounted",
                "MEDIUM",
                "Identity",
                path,
                None,
                "Pod does not explicitly disable automatic service-account token mounting.",
                "Set automountServiceAccountToken: false when Kubernetes API access is unnecessary.",
            )
        )

    pod_security = pod_spec.get("securityContext") or {}
    seccomp = pod_security.get("seccompProfile") or {}
    if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
        findings.append(
            _finding(
                "AEGIS-K8S-014",
                "Seccomp profile not configured",
                "MEDIUM",
                "Workload",
                path,
                None,
                "Pod does not configure a RuntimeDefault or Localhost seccomp profile.",
                "Set securityContext.seccompProfile.type to RuntimeDefault or an approved Localhost profile.",
            )
        )

    pod_run_as_non_root = pod_security.get("runAsNonRoot") is True

    for container in pod_spec.get("containers", []) or []:
        if not isinstance(container, dict):
            continue
        security = container.get("securityContext") or {}
        name = container.get("name", "container")

        if security.get("privileged") is True:
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-002",
                    "Privileged container",
                    "CRITICAL",
                    "runs in privileged mode",
                    "Remove privileged mode and grant only required capabilities.",
                )
            )

        if security.get("allowPrivilegeEscalation") is not False:
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-003",
                    "Privilege escalation not disabled",
                    "HIGH",
                    "does not explicitly disable privilege escalation",
                    "Set securityContext.allowPrivilegeEscalation: false.",
                )
            )

        resources = container.get("resources") or {}
        if not resources.get("requests") or not resources.get("limits"):
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-004",
                    "Missing resource requests or limits",
                    "MEDIUM",
                    "is missing resource requests or limits",
                    "Define CPU and memory requests and limits.",
                    category="Reliability",
                )
            )

        image = str(container.get("image", ""))
        if image.endswith(":latest") or (image and ":" not in image and "@sha256:" not in image):
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-005",
                    "Mutable container image tag",
                    "MEDIUM",
                    "uses a mutable or unpinned image tag",
                    "Pin deployments to an immutable version tag or image digest.",
                    category="Supply Chain",
                )
            )

        if security.get("runAsNonRoot") is not True and not pod_run_as_non_root:
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-006",
                    "Container may run as root",
                    "HIGH",
                    "does not explicitly require a non-root user",
                    "Set runAsNonRoot: true at pod or container level.",
                )
            )

        if security.get("readOnlyRootFilesystem") is not True:
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-007",
                    "Writable root filesystem",
                    "MEDIUM",
                    "does not use a read-only root filesystem",
                    "Set securityContext.readOnlyRootFilesystem: true where supported.",
                )
            )

        capabilities = security.get("capabilities") or {}
        dropped = {str(item).upper() for item in capabilities.get("drop", []) or []}
        if "ALL" not in dropped:
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-008",
                    "Linux capabilities not fully dropped",
                    "MEDIUM",
                    "does not drop all Linux capabilities by default",
                    "Set securityContext.capabilities.drop: [\"ALL\"] and add back only what is required.",
                )
            )

        if not container.get("readinessProbe"):
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-015",
                    "Missing readiness probe",
                    "LOW",
                    "does not define a readiness probe",
                    "Add a readinessProbe that reflects application readiness.",
                    category="Reliability",
                )
            )

        if not container.get("livenessProbe"):
            findings.append(
                _container_finding(
                    path,
                    name,
                    "AEGIS-K8S-016",
                    "Missing liveness probe",
                    "LOW",
                    "does not define a liveness probe",
                    "Add a livenessProbe appropriate for the workload.",
                    category="Reliability",
                )
            )


def _iter_tf_resources(parsed: dict[str, Any]):
    for resource_group in parsed.get("resource", []) or []:
        if not isinstance(resource_group, dict):
            continue
        for resource_type, instances in resource_group.items():
            if not isinstance(instances, dict):
                continue
            for name, attrs in instances.items():
                if isinstance(attrs, dict):
                    yield str(resource_type), str(name), attrs

    for data_group in parsed.get("data", []) or []:
        if not isinstance(data_group, dict):
            continue
        for resource_type, instances in data_group.items():
            if resource_type != "aws_iam_policy_document" or not isinstance(instances, dict):
                continue
            for name, attrs in instances.items():
                if isinstance(attrs, dict):
                    yield str(resource_type), str(name), attrs


def _has_public_ingress(resource_type: str, attrs: dict[str, Any]) -> bool:
    if resource_type == "aws_security_group_rule":
        if attrs.get("type") != "ingress":
            return False
        return _contains_open_cidr(attrs.get("cidr_blocks")) or _contains_open_cidr(
            attrs.get("ipv6_cidr_blocks")
        )

    for ingress in attrs.get("ingress", []) or []:
        if not isinstance(ingress, dict):
            continue
        if _contains_open_cidr(ingress.get("cidr_blocks")):
            return True
        if _contains_open_cidr(ingress.get("ipv6_cidr_blocks")):
            return True
    return False


def _contains_open_cidr(value: Any) -> bool:
    if isinstance(value, str):
        return value in OPEN_CIDRS
    if isinstance(value, list):
        return any(_contains_open_cidr(item) for item in value)
    return False


def _contains_wildcard_action(value: Any, key: str = "") -> bool:
    if isinstance(value, dict):
        for child_key, child in value.items():
            if _contains_wildcard_action(child, str(child_key).lower()):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_wildcard_action(item, key) for item in value)
    if isinstance(value, str):
        if key in {"action", "actions"} and value.strip() == "*":
            return True
        if key == "policy" and re.search(r'"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])', value):
            return True
    return False


def _first_block(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _resource_line(text: str, resource_type: str, name: str) -> int | None:
    pattern = re.compile(
        rf'^\s*(?:resource|data)\s+"{re.escape(resource_type)}"\s+"{re.escape(name)}"',
        re.MULTILINE,
    )
    match = pattern.search(text)
    return text[: match.start()].count("\n") + 1 if match else None


def _pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        return ((spec.get("template") or {}).get("spec") or {})
    if kind == "CronJob":
        job = (spec.get("jobTemplate") or {}).get("spec") or {}
        return ((job.get("template") or {}).get("spec") or {})
    return None


def _k8s_flag(path: Path, rule_id: str, title: str, field: str) -> Finding:
    return _finding(
        rule_id,
        title,
        "HIGH",
        "Workload",
        path,
        None,
        f"Pod sets {field}: true and shares a host namespace.",
        f"Set {field}: false unless host namespace access is explicitly required.",
    )


def _container_finding(
    path: Path,
    name: str,
    rule_id: str,
    title: str,
    severity: str,
    issue: str,
    remediation: str,
    category: str = "Workload",
) -> Finding:
    return _finding(
        rule_id,
        title,
        severity,
        category,
        path,
        None,
        f"Container '{name}' {issue}.",
        remediation,
    )


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    path: Path,
    line: int | None,
    message: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        file=str(path),
        line=line,
        message=message,
        remediation=remediation,
    )

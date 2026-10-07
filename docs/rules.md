# AegisScan Rule Reference

AegisScan uses first-party rule IDs so findings remain stable across terminal, JSON, HTML, SARIF, CI, and suppression workflows.

## AWS / Terraform rules

| Rule | Severity | What it detects | Recommended remediation |
| --- | --- | --- | --- |
| AEGIS-AWS-001 | High | Security-group ingress open to `0.0.0.0/0` or `::/0` | Restrict ingress to trusted CIDRs or security-group references. |
| AEGIS-AWS-002 | Critical | Public or authenticated-read S3 ACL | Use private ACLs and S3 Block Public Access. |
| AEGIS-AWS-003 | Critical | Publicly accessible RDS instance | Use private subnets and set `publicly_accessible = false`. |
| AEGIS-AWS-004 | Medium | EBS volume without explicit encryption | Set `encrypted = true`. |
| AEGIS-AWS-005 | High | IAM policy containing wildcard actions | Replace wildcards with least-privilege actions. |
| AEGIS-AWS-006 | High | S3 Block Public Access controls not fully enabled | Enable all four public-access-block controls unless intentionally exempted. |
| AEGIS-AWS-007 | High | RDS storage encryption not enabled | Set `storage_encrypted = true` and use an approved KMS key when required. |
| AEGIS-AWS-008 | Medium | EFS encryption not enabled | Set `encrypted = true`. |
| AEGIS-AWS-009 | Medium | CloudTrail log validation not enabled | Set `enable_log_file_validation = true`. |
| AEGIS-AWS-010 | Medium | CloudTrail not configured as multi-region | Set `is_multi_region_trail = true`. |
| AEGIS-AWS-011 | Medium | KMS automatic key rotation not enabled | Enable automatic key rotation where supported. |
| AEGIS-AWS-012 | High | EC2 public IP association enabled | Prefer private subnets and controlled ingress. |
| AEGIS-AWS-013 | High | EC2 IMDSv2 not enforced | Set `metadata_options.http_tokens = "required"`. |
| AEGIS-AWS-014 | Medium | EC2 root volume encryption not enabled | Encrypt the root block device. |

## Kubernetes rules

| Rule | Severity | What it detects | Recommended remediation |
| --- | --- | --- | --- |
| AEGIS-K8S-001 | Medium | `LoadBalancer` service exposure | Confirm public exposure is required or use controlled ingress. |
| AEGIS-K8S-002 | Critical | Privileged container | Remove privileged mode and grant only required capabilities. |
| AEGIS-K8S-003 | High | Privilege escalation not explicitly disabled | Set `allowPrivilegeEscalation: false`. |
| AEGIS-K8S-004 | Medium | Missing CPU/memory requests or limits | Define requests and limits. |
| AEGIS-K8S-005 | Medium | Mutable or unpinned image tag | Pin a version or immutable digest. |
| AEGIS-K8S-006 | High | Container may run as root | Set `runAsNonRoot: true` and a non-root UID where appropriate. |
| AEGIS-K8S-007 | Medium | Writable root filesystem | Set `readOnlyRootFilesystem: true` when supported. |
| AEGIS-K8S-008 | Medium | Linux capabilities not fully dropped | Drop `ALL` capabilities and add back only those required. |
| AEGIS-K8S-009 | High | Host network namespace enabled | Avoid `hostNetwork` unless strictly required. |
| AEGIS-K8S-010 | High | Host PID namespace enabled | Avoid `hostPID` unless strictly required. |
| AEGIS-K8S-011 | High | Host IPC namespace enabled | Avoid `hostIPC` unless strictly required. |
| AEGIS-K8S-012 | High | HostPath volume mounted | Avoid hostPath or scope it tightly and preferably read-only. |
| AEGIS-K8S-013 | Medium | Service-account token automatically mounted | Set `automountServiceAccountToken: false` when API access is unnecessary. |
| AEGIS-K8S-014 | Medium | Seccomp profile not configured | Use `RuntimeDefault` or an approved `Localhost` profile. |
| AEGIS-K8S-015 | Low | Missing readiness probe | Add an application-appropriate readiness probe. |
| AEGIS-K8S-016 | Low | Missing liveness probe | Add an application-appropriate liveness probe. |
| AEGIS-K8S-017 | Medium | NodePort service exposure | Prefer ClusterIP with controlled ingress unless NodePort is required. |

## Suppressions

A file can suppress a reviewed finding using:

```text
# aegisscan:ignore AEGIS-AWS-001
```

Suppressions are intended for documented risk acceptance, not for hiding unresolved findings.

## Severity model

- **Critical**: direct public exposure or highly dangerous workload configuration.
- **High**: significant attack-path or privilege risk.
- **Medium**: meaningful hardening, encryption, identity, or operational security weakness.
- **Low**: defense-in-depth or reliability control that should still be addressed.

The security score is a prioritization aid and is not a compliance certification.

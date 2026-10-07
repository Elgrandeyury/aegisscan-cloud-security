from pathlib import Path

from aegisscan.rules import scan_kubernetes, scan_terraform


def test_terraform_detects_public_ingress_public_rds_and_rds_encryption():
    text = '''
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
'''
    findings = scan_terraform(Path("main.tf"), text)
    ids = {finding.rule_id for finding in findings}
    assert "AEGIS-AWS-001" in ids
    assert "AEGIS-AWS-003" in ids
    assert "AEGIS-AWS-007" in ids


def test_terraform_detects_cloudtrail_kms_and_ec2_controls():
    text = '''
resource "aws_cloudtrail" "audit" {
  enable_log_file_validation = false
  is_multi_region_trail      = false
}

resource "aws_kms_key" "app" {
  enable_key_rotation = false
}

resource "aws_instance" "app" {
  associate_public_ip_address = true
  metadata_options {
    http_tokens = "optional"
  }
  root_block_device {
    encrypted = false
  }
}
'''
    ids = {finding.rule_id for finding in scan_terraform(Path("main.tf"), text)}
    assert {"AEGIS-AWS-009", "AEGIS-AWS-010", "AEGIS-AWS-011"} <= ids
    assert {"AEGIS-AWS-012", "AEGIS-AWS-013", "AEGIS-AWS-014"} <= ids


def test_terraform_secure_resources_do_not_trigger_expected_rules():
    text = '''
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
resource "aws_efs_file_system" "data" {
  encrypted = true
}
resource "aws_kms_key" "app" {
  enable_key_rotation = true
}
resource "aws_instance" "app" {
  associate_public_ip_address = false
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
}
'''
    ids = {finding.rule_id for finding in scan_terraform(Path("secure.tf"), text)}
    blocked = {
        "AEGIS-AWS-003",
        "AEGIS-AWS-007",
        "AEGIS-AWS-008",
        "AEGIS-AWS-011",
        "AEGIS-AWS-012",
        "AEGIS-AWS-013",
        "AEGIS-AWS-014",
    }
    assert ids.isdisjoint(blocked)


def test_kubernetes_detects_privileged_root_host_access_and_weak_hardening():
    text = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  selector:
    matchLabels:
      app: bad
  template:
    metadata:
      labels:
        app: bad
    spec:
      hostNetwork: true
      hostPID: true
      automountServiceAccountToken: true
      volumes:
        - name: host
          hostPath:
            path: /etc
      containers:
        - name: app
          image: nginx:latest
          volumeMounts:
            - name: host
              mountPath: /host
          securityContext:
            privileged: true
'''
    ids = {finding.rule_id for finding in scan_kubernetes(Path("deployment.yaml"), text)}
    assert {"AEGIS-K8S-002", "AEGIS-K8S-003", "AEGIS-K8S-004", "AEGIS-K8S-005"} <= ids
    assert {"AEGIS-K8S-006", "AEGIS-K8S-007", "AEGIS-K8S-008"} <= ids
    assert {"AEGIS-K8S-009", "AEGIS-K8S-010", "AEGIS-K8S-012", "AEGIS-K8S-013"} <= ids
    assert {"AEGIS-K8S-014", "AEGIS-K8S-015", "AEGIS-K8S-016"} <= ids


def test_kubernetes_hardened_workload_avoids_hardening_findings():
    text = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure
spec:
  selector:
    matchLabels:
      app: secure
  template:
    metadata:
      labels:
        app: secure
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: nginx:1.27.5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 250m
              memory: 128Mi
          readinessProbe:
            httpGet:
              path: /
              port: 80
          livenessProbe:
            httpGet:
              path: /
              port: 80
'''
    ids = {finding.rule_id for finding in scan_kubernetes(Path("secure.yaml"), text)}
    blocked = {
        "AEGIS-K8S-002",
        "AEGIS-K8S-003",
        "AEGIS-K8S-004",
        "AEGIS-K8S-005",
        "AEGIS-K8S-006",
        "AEGIS-K8S-007",
        "AEGIS-K8S-008",
        "AEGIS-K8S-013",
        "AEGIS-K8S-014",
        "AEGIS-K8S-015",
        "AEGIS-K8S-016",
    }
    assert ids.isdisjoint(blocked)

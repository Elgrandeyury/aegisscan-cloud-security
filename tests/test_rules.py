from pathlib import Path

from aegisscan.rules import scan_kubernetes, scan_terraform


def test_terraform_detects_public_ingress_and_public_rds():
    text = '''
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
}
'''
    findings = scan_terraform(Path("main.tf"), text)
    ids = {finding.rule_id for finding in findings}
    assert "AEGIS-AWS-001" in ids
    assert "AEGIS-AWS-003" in ids


def test_kubernetes_detects_privileged_latest_and_missing_resources():
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
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
'''
    findings = scan_kubernetes(Path("deployment.yaml"), text)
    ids = {finding.rule_id for finding in findings}
    assert "AEGIS-K8S-002" in ids
    assert "AEGIS-K8S-003" in ids
    assert "AEGIS-K8S-004" in ids
    assert "AEGIS-K8S-005" in ids

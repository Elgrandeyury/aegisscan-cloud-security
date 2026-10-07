from pathlib import Path

from aegisscan.config import ScanConfig
from aegisscan.engine import scan_path


def test_disabled_rule_and_inline_suppression(tmp_path: Path):
    tf = tmp_path / "main.tf"
    tf.write_text(
        '''
# aegisscan:ignore AEGIS-AWS-003
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = true
}
''',
        encoding="utf-8",
    )

    config = ScanConfig(disabled_rules={"AEGIS-AWS-001"})
    findings, files_scanned = scan_path(tmp_path, config=config)

    assert files_scanned == 1
    assert findings == []


def test_ignore_paths_and_minimum_severity(tmp_path: Path):
    ignored = tmp_path / "vendor"
    ignored.mkdir()
    (ignored / "bad.tf").write_text(
        'resource "aws_db_instance" "db" { publicly_accessible = true }',
        encoding="utf-8",
    )
    kept = tmp_path / "deployment.yaml"
    kept.write_text(
        '''
apiVersion: v1
kind: Service
metadata:
  name: public
spec:
  type: LoadBalancer
''',
        encoding="utf-8",
    )

    config = ScanConfig(ignored_paths=["vendor/**"], minimum_severity="high")
    findings, files_scanned = scan_path(tmp_path, config=config)

    assert files_scanned == 1
    assert findings == []

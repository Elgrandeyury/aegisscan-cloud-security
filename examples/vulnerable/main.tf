resource "aws_security_group" "open_web" {
  name = "open-web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "database" {
  identifier          = "demo-db"
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_iam_policy" "admin" {
  name = "overly-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
}

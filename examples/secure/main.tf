resource "aws_db_instance" "app" {
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_ebs_volume" "data" {
  encrypted = true
}

resource "aws_efs_file_system" "shared" {
  encrypted = true
}

resource "aws_kms_key" "app" {
  enable_key_rotation = true
}

resource "aws_cloudtrail" "audit" {
  enable_log_file_validation = true
  is_multi_region_trail      = true
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

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = "example"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

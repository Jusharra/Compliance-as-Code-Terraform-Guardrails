# Who am I?
data "aws_caller_identity" "current" {}

# KMS key for CloudTrail/S3 encryption
resource "aws_kms_key" "log_kms" {
  description             = "KMS key for log bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Root admin
      {
        Sid : "EnableRootPermissions",
        Effect : "Allow",
        Principal : { AWS : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action : "kms:*",
        Resource : "*"
      },
      # Allow CloudTrail to generate data keys + encrypt to this CMK
      {
        Sid : "AllowCloudTrailUseOfTheKey",
        Effect : "Allow",
        Principal : { Service : "cloudtrail.amazonaws.com" },
        Action : [
          "kms:GenerateDataKey*",
          "kms:Encrypt",
          "kms:DescribeKey"
        ],
        Resource : "*",
        Condition : {
          StringLike : {
            "kms:EncryptionContext:aws:cloudtrail:arn" : "arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${var.name_prefix}-trail"
          }
        }
      }
    ]
  })
  tags = var.tags
}

data "aws_iam_policy_document" "kms_policy" {
  # Root can administer the key
  statement {
    sid = "EnableRootPermissions"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow CloudTrail and S3 to use the key for SSE-KMS
  statement {
    sid = "AllowServicesUseOfKey"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "s3.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "${var.name_prefix}-logs-${random_id.rand.hex}"
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket" "access_logs_target" {
  bucket        = "${var.name_prefix}-s3-access-logs-${random_id.rand.hex}"
  force_destroy = true
  tags          = var.tags
}

# Make S3 the owner of uploaded objects (helps cross-service writes)
resource "aws_s3_bucket_ownership_controls" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_ownership_controls" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "access_logs_target" {
  bucket                  = aws_s3_bucket.access_logs_target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning
resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration { status = "Enabled" }
}

# Optional but recommended: versioning + lifecycle
resource "aws_s3_bucket_versioning" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    expiration { days = 365 }
    filter {}
  }
}

# **Default SSE with KMS key**
resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_kms.arn
    }
    bucket_key_enabled = true
  }
}
resource "random_id" "rand" { byte_length = 4 }

# Allow S3 server-access logging to write objects with bucket-owner-full-control
resource "aws_s3_bucket_policy" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid : "S3ServerAccessLogsPolicy",
      Effect : "Allow",
      Principal : { Service : "logging.s3.amazonaws.com" },
      Action : "s3:PutObject",
      Resource : "arn:aws:s3:::${aws_s3_bucket.access_logs_target.id}/*",
      Condition : {
        StringEquals : { "s3:x-amz-acl" : "bucket-owner-full-control" }
      }
    }]
  })
}

# Turn on access logging for your primary log bucket
resource "aws_s3_bucket_logging" "log_bucket" {
  bucket        = aws_s3_bucket.log_bucket.id
  target_bucket = aws_s3_bucket.access_logs_target.id
  target_prefix = "s3-access/${aws_s3_bucket.log_bucket.id}/"
}

resource "aws_cloudtrail" "org_trail" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  s3_key_prefix                 = "AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/${var.region}"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.log_kms.arn

  # If you also wire CloudWatch Logs, keep your existing role/log group
  # cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"  # note :*
  # cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cw.arn

  tags = var.tags
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
  tags       = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

# Example least-privilege IAM role for workloads
data "aws_iam_policy_document" "least_privilege" {
  statement {
    sid       = "AllowSpecificKMSUsage"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [aws_kms_key.log_kms.arn]
  }
}
resource "aws_iam_role" "workload" {
  name = "${var.name_prefix}-workload-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}
resource "aws_iam_policy" "workload_policy" {
  name   = "${var.name_prefix}-lp-policy"
  policy = data.aws_iam_policy_document.least_privilege.json
}
resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.workload.name
  policy_arn = aws_iam_policy.workload_policy.arn
}


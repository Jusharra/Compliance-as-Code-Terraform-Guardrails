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

# SSE-KMS for access logs target bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id

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
  # Use a simple prefix to avoid InvalidS3PrefixException
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.log_kms.arn

  # Integrate with CloudWatch Logs and SNS for notifications
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cw.arn
  sns_topic_name              = aws_sns_topic.cloudtrail_notifications.name

  # If you also wire CloudWatch Logs, keep your existing role/log group
  # cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"  # note :*
  # cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cw.arn

  tags = var.tags
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
  tags       = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

# Lock down the default security group: deny all ingress/egress
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # No ingress/egress rules means deny by default
  lifecycle { create_before_destroy = true }
  tags = merge(var.tags, { Name = "${var.name_prefix}-default-sg-locked" })
}

# VPC Flow Logs to CloudWatch
resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/flow/${var.name_prefix}"
  retention_in_days = 90
  tags              = var.tags
}

resource "aws_iam_role" "vpc_flow_to_cw" {
  name = "${var.name_prefix}-vpc-flow-to-cw"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "vpc-flow-logs.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "vpc_flow_to_cw" {
  name = "${var.name_prefix}-vpc-flow-to-cw"
  role = aws_iam_role.vpc_flow_to_cw.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
      Resource = "${aws_cloudwatch_log_group.vpc_flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  log_destination_type = "cloud-watch-logs"
  # Use destination ARN per deprecation of log_group_name
  log_destination      = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn         = aws_iam_role.vpc_flow_to_cw.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
  tags                 = var.tags
}

# CloudTrail -> CloudWatch logs + SNS
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 90
  tags              = var.tags
}

resource "aws_iam_role" "trail_to_cw" {
  name = "${var.name_prefix}-trail-to-cw"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "cloudtrail.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "trail_to_cw" {
  name = "${var.name_prefix}-trail-to-cw"
  role = aws_iam_role.trail_to_cw.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

resource "aws_sns_topic" "cloudtrail_notifications" {
  name = "${var.name_prefix}-cloudtrail-notifications"
  tags = var.tags
}

# S3 event notifications to SNS
resource "aws_sns_topic" "s3_events" {
  name = "${var.name_prefix}-s3-events"
  tags = var.tags
}

data "aws_iam_policy_document" "s3_events_topic" {
  statement {
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    resources = [aws_sns_topic.s3_events.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [
        "arn:aws:s3:::${aws_s3_bucket.log_bucket.id}",
        "arn:aws:s3:::${aws_s3_bucket.access_logs_target.id}"
      ]
    }
  }
}

resource "aws_sns_topic_policy" "s3_events" {
  arn    = aws_sns_topic.s3_events.arn
  policy = data.aws_iam_policy_document.s3_events_topic.json
}

resource "aws_s3_bucket_notification" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.s3_events]
}

resource "aws_s3_bucket_notification" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.s3_events]
}

# ----------------------
# Cross-Region Replication
# ----------------------

# Destination KMS key in replica region
resource "aws_kms_key" "replica_kms" {
  provider                 = aws.replica
  description              = "KMS key for replica log bucket encryption"
  deletion_window_in_days  = 7
  enable_key_rotation      = true
  tags                     = var.tags
}

# Destination buckets in replica region
resource "aws_s3_bucket" "log_bucket_replica" {
  provider      = aws.replica
  bucket        = "${var.name_prefix}-logs-replica-${random_id.rand.hex}"
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket" "access_logs_target_replica" {
  provider      = aws.replica
  bucket        = "${var.name_prefix}-s3-access-logs-replica-${random_id.rand.hex}"
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket_ownership_controls" "log_bucket_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.log_bucket_replica.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_ownership_controls" "access_logs_target_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.access_logs_target_replica.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "log_bucket_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.log_bucket_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "access_logs_target_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.access_logs_target_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "log_bucket_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.log_bucket_replica.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "access_logs_target_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.access_logs_target_replica.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.log_bucket_replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica_kms.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs_target_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.access_logs_target_replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica_kms.arn
    }
    bucket_key_enabled = true
  }
}

# Replication role
resource "aws_iam_role" "s3_replication" {
  name = "${var.name_prefix}-s3-replication-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "s3.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

data "aws_iam_policy_document" "s3_replication" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.log_bucket.arn,
      aws_s3_bucket.access_logs_target.arn
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObjectVersion",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectLegalHold",
      "s3:GetObjectVersionTagging",
      "s3:ObjectOwnerOverrideToBucketOwner"
    ]
    resources = [
      "${aws_s3_bucket.log_bucket.arn}/*",
      "${aws_s3_bucket.access_logs_target.arn}/*"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags",
      "s3:PutObjectAcl"
    ]
    resources = [
      "${aws_s3_bucket.log_bucket_replica.arn}/*",
      "${aws_s3_bucket.access_logs_target_replica.arn}/*"
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.log_kms.arn,
      aws_kms_key.replica_kms.arn
    ]
  }
}

resource "aws_iam_role_policy" "s3_replication" {
  name   = "${var.name_prefix}-s3-replication-policy"
  role   = aws_iam_role.s3_replication.id
  policy = data.aws_iam_policy_document.s3_replication.json
}

resource "aws_s3_bucket_replication_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    # Required when source bucket uses SSE-KMS
    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.log_bucket_replica.arn
      storage_class = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica_kms.arn
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.log_bucket,
    aws_s3_bucket_versioning.log_bucket_replica
  ]
}

resource "aws_s3_bucket_replication_configuration" "access_logs_target" {
  bucket = aws_s3_bucket.access_logs_target.id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    # Required when source bucket uses SSE-KMS
    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket             = aws_s3_bucket.access_logs_target_replica.arn
      storage_class      = "STANDARD"
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica_kms.arn
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.access_logs_target,
    aws_s3_bucket_versioning.access_logs_target_replica
  ]
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


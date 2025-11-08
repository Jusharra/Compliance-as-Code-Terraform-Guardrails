resource "aws_kms_key" "log_kms" {
  description             = "KMS key for log bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_s3_bucket" "log_bucket" {
  bucket        = "${var.name_prefix}-logs-${random_id.rand.hex}"
  force_destroy = true
  tags          = var.tags
}
resource "random_id" "rand" { byte_length = 4 }

resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_kms.arn
    }
  }
}

resource "aws_cloudtrail" "org_trail" {
  s3_bucket_name                = "cac-demo-logs-8d5e3627"
  name                          = "cac-demo-trail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "arn:aws:kms:us-east-1:281517525855:key/8b6e6328-74fc-4ab1-aec8-ad5a68cde9be"
  tags                          = var.tags
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






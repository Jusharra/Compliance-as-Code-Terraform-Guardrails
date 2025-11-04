output "region" {
  value = var.region
}
output "trail_name" { value = aws_cloudtrail.org_trail.name }
output "log_bucket" { value = aws_s3_bucket.log_bucket.id }
output "kms_key_id" { value = aws_kms_key.log_kms.id }

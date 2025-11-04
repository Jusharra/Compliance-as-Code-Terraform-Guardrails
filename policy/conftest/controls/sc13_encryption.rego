package main

# Require S3 default encryption with KMS
deny contains msg if {
  rc := resource_changes_by_type["aws_s3_bucket_server_side_encryption_configuration"][_]
  sse := after(rc)
  not sse.rule.apply_server_side_encryption_by_default.kms_master_key_id
  msg := sprintf("SC-13: S3 bucket %q SSE missing KMS key id.", [sse.bucket])
}

# Require CloudTrail kms_key_id
deny contains msg if {
  rc := resource_changes_by_type["aws_cloudtrail"][_]
  ct := after(rc)
  not ct.kms_key_id
  msg := sprintf("SC-13: CloudTrail %q missing kms_key_id.", [ct.name])
}

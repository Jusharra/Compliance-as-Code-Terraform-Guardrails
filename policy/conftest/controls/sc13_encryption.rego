package controls.sc13

import data.tfplan

deny[msg] {
  some r
  tfplan.is_resource_type(r, "aws_s3_bucket_server_side_encryption_configuration")
  sse := r.change.after
  not sse.rule[0].apply_server_side_encryption_by_default.kms_master_key_id
  msg := sprintf("SC-13: S3 SSE-KMS key not specified for %v", [r.address])
}


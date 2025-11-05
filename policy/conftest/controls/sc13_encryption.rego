package main

# Require S3 default encryption with KMS
deny contains msg if {
  rc := resource_changes_by_type("aws_s3_bucket_server_side_encryption_configuration")[_]
  sse := after(rc)
  # Normalize rules: Terraform plan can emit 'rule' as a single object or a list
  r := sse_rules(sse)[_]
  not kms_id_present(r)
  # Skip deny if Terraform marks the kms_master_key_id as unknown in plan (e.g., referencing a key created in the same plan)
  not kms_id_marked_unknown(rc)
  msg := sprintf("SC-13: S3 bucket %q SSE missing KMS key id.", [sse.bucket])
}

# Require CloudTrail kms_key_id
deny contains msg if {
  rc := resource_changes_by_type("aws_cloudtrail")[_]
  ct := after(rc)
  not ct.kms_key_id
  msg := sprintf("SC-13: CloudTrail %q missing kms_key_id.", [ct.name])
}

# Helper: returns true if plan marks the kms_master_key_id as unknown anywhere under after_unknown
kms_id_marked_unknown(rc) if {
  au := rc.change.after_unknown
  some p, v
  walk(au, [p, v])
  p[_] == "kms_master_key_id"
  v == true
}

# Helper: normalize 'rule' to a list
sse_rules(sse) := sse.rule if {
  is_array(sse.rule)
}
sse_rules(sse) := [sse.rule] if {
  not is_array(sse.rule)
}

# Helper: return true if kms_master_key_id exists whether the field is a list or object
kms_id_present(r) if {
  # list shape
  is_array(r.apply_server_side_encryption_by_default)
  some i
  r.apply_server_side_encryption_by_default[i].kms_master_key_id
}
kms_id_present(r) if {
  # object shape
  not is_array(r.apply_server_side_encryption_by_default)
  r.apply_server_side_encryption_by_default.kms_master_key_id
}

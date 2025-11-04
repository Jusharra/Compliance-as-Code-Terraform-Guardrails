package main

# S3 Public Access Block must be strict
deny contains msg if {
  rc := resource_changes_by_type["aws_s3_bucket_public_access_block"][_]
  pab := after(rc)
  not pab.block_public_acls
  msg := sprintf("CM-6: S3 bucket %q public access block: block_public_acls=false.", [pab.bucket])
}

deny contains msg if {
  rc := resource_changes_by_type["aws_s3_bucket_public_access_block"][_]
  pab := after(rc)
  not pab.block_public_policy
  msg := sprintf("CM-6: S3 bucket %q public access block: block_public_policy=false.", [pab.bucket])
}

# S3 versioning must be Enabled
deny contains msg if {
  rc := resource_changes_by_type["aws_s3_bucket_versioning"][_]
  ver := after(rc)
  ver.versioning_configuration.status != "Enabled"
  msg := sprintf("CM-6: S3 bucket %q versioning not Enabled.", [ver.bucket])
}

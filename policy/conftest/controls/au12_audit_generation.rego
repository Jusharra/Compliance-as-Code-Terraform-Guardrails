package main

# CloudTrail must be multi-region, log validation enabled, and wired to CW Logs + SNS
deny[msg] {
  rc := resource_changes_by_type("aws_cloudtrail")[_]
  ct := after(rc)
  not ct.is_multi_region_trail
  msg := sprintf("AU-12: CloudTrail %q is not multi-region.", [ct.name])
}

deny[msg] {
  rc := resource_changes_by_type("aws_cloudtrail")[_]
  ct := after(rc)
  not ct.enable_log_file_validation
  msg := sprintf("AU-12: CloudTrail %q missing log file validation.", [ct.name])
}

deny[msg] {
  rc := resource_changes_by_type("aws_cloudtrail")[_]
  ct := after(rc)
  not ct.cloud_watch_logs_group_arn
  msg := sprintf("AU-12: CloudTrail %q not integrated with CloudWatch Logs.", [ct.name])
}

deny[msg] {
  rc := resource_changes_by_type("aws_cloudtrail")[_]
  ct := after(rc)
  not ct.sns_topic_name
  msg := sprintf("AU-12: CloudTrail %q not publishing to SNS.", [ct.name])
}



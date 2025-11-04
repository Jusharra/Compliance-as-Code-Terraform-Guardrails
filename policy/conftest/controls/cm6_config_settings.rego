package controls.cm6_config_settings

deny[msg] {
  input.resource_type == "aws_iam_policy"
  msg := "Policy cm6_config_settings not satisfied"
}

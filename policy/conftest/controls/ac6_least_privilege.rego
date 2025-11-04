package controls.ac6_least_privilege

deny[msg] {
  input.resource_type == "aws_iam_policy"
  msg := "Policy ac6_least_privilege not satisfied"
}

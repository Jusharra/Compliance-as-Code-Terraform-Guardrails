package controls.au12_audit_generation

deny[msg] {
  input.resource_type == "aws_iam_policy"
  msg := "Policy au12_audit_generation not satisfied"
}

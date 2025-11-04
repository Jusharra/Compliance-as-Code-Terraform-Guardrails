package controls.sc13_encryption

deny[msg] {
  input.resource_type == "aws_iam_policy"
  msg := "Policy sc13_encryption not satisfied"
}

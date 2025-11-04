package controls.sc7_network_segmentation

deny[msg] {
  input.resource_type == "aws_iam_policy"
  msg := "Policy sc7_network_segmentation not satisfied"
}

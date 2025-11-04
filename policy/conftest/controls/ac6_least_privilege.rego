package controls.ac6

import data.tfplan

deny[msg] {
  some r
  tfplan.is_resource_type(r, "aws_iam_policy")
  r.change.after.policy != ""
  policy := json.unmarshal(r.change.after.policy)
  some i
  actions := policy.Statement[i].Action
  actions == "*"
  msg := sprintf("AC-6: Policy %v uses Action:* (least privilege violated)", [r.address])
}


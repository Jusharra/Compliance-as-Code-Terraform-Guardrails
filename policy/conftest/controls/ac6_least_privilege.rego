package main

# Disallow IAM policies that allow Action:"*"
deny contains msg if {
  rc := resource_changes_by_type["aws_iam_policy"][_]
  pol := after(rc)
  pol.policy != null
  parsed := json.unmarshal(pol.policy)
  stmt := parsed.Statement[_]
  stmt.Effect == "Allow"
  stmt.Action == "*"
  msg := sprintf("AC-6: IAM policy %q allows Action \"*\"", [pol.name])
}

# Disallow IAM policies that allow Resource:"*"
deny contains msg if {
  rc := resource_changes_by_type["aws_iam_policy"][_]
  pol := after(rc)
  pol.policy != null
  parsed := json.unmarshal(pol.policy)
  stmt := parsed.Statement[_]
  stmt.Effect == "Allow"
  stmt.Resource == "*"
  msg := sprintf("AC-6: IAM policy %q allows Resource \"*\"", [pol.name])
}
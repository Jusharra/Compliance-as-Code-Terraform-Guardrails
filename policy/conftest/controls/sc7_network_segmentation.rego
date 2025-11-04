package controls.sc7

import data.tfplan

default deny = []

deny[msg] {
  some r
  tfplan.is_resource_type(r, "aws_security_group_rule")
  after := r.change.after
  after.type == "ingress"
  after.cidr_blocks[_] == "0.0.0.0/0"
  # flag common admin ports
  after.from_port <= 22
  after.to_port >= 22
  msg := sprintf("SC-7: Ingress 0.0.0.0/0 on port 22 for %v", [r.address])
}


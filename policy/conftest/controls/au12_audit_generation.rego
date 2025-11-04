package controls.au12

import data.tfplan

deny[msg] {
  some r
  tfplan.is_resource_type(r, "aws_cloudtrail")
  trail := r.change.after
  not trail.is_multi_region_trail
  msg := sprintf("AU-12: CloudTrail is not multi-region (%v)", [r.address])
}


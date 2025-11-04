package controls.cm6

import data.tfplan

required := {"Owner","Environment","System"}

deny[msg] {
  some r
  tags := r.change.after.tags
  required[k]
  not tags[required[k]]
  msg := sprintf("CM-6: Missing required tag %v on %v", [required[k], r.address])
}


package main

# Convenience to iterate over "after" objects in input.resource_changes
after_objects[a] {
  some i
  rc := input.resource_changes[i]
  rc.change.after != null
  a := rc.change.after
  a_type := rc.type
}

# Get resource_changes by type (e.g., "aws_s3_bucket")
resource_changes_by_type(t)[rc] {
  some i
  rc := input.resource_changes[i]
  rc.type == t
}

# Extract the "after" for a given resource_change
after(rc) = a {
  rc.change.after != null
  a := rc.change.after
}

# Utility: true if a list contains a value
contains(arr, v) {
  some i
  arr[i] == v
}

# Utility: true if CIDR list contains 0.0.0.0/0
has_cidr_any(cidr_blocks) {
  cidr_blocks[_] == "0.0.0.0/0"
}



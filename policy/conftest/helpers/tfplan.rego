package main

# Set of "after" objects from input.resource_changes
after_objects contains a if {
  some i
  rc := input.resource_changes[i]
  rc.change.after != null
  a := rc.change.after
}

# Set of resource_changes filtered by type (e.g., "aws_s3_bucket")
resource_changes_by_type[t] contains rc if {
  some i
  rc := input.resource_changes[i]
  rc.type == t
}

# Function: extract "after" portion from a change
after(rc) := a if {
  rc.change.after != null
  a := rc.change.after
}

# True if list has "0.0.0.0/0"
has_cidr_any(arr) if {
  arr[_] == "0.0.0.0/0"
}

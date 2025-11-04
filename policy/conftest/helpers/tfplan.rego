package main

# Collect the "after" objects from input.resource_changes
after_objects contains a if {
  rc := input.resource_changes[_]
  rc.change.after != null
  a := rc.change.after
}

# Function: get all resource_changes for a given type (returns a list)
resource_changes_by_type(t) := out if {
  out := [rc |
    rc := input.resource_changes[_]
    rc.type == t
  ]
}

# Function: extract "after" portion
after(rc) := a if {
  rc.change.after != null
  a := rc.change.after
}

# True if list has "0.0.0.0/0"
has_cidr_any(arr) if {
  arr[_] == "0.0.0.0/0"
}

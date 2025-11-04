package tfplan

is_resource_type(res, type) {
  res.resource_type == type
}

input_resources := [r | some i
  r := input.resource_changes[i]
]


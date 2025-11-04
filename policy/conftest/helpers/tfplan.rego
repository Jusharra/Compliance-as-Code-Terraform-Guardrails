package helpers.tfplan

get_resources(resources) = resources {
  resources := input.resource_changes[_]
}

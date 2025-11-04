package main

# Sensitive ingress if:
#  - protocol all (-1), or
#  - TCP 22 (SSH), or
#  - TCP 3389 (RDP)

sensitive_ingress(ing) if {
  ing.protocol == "-1"
}

sensitive_ingress(ing) if {
  ing.protocol == "tcp"
  ing.from_port <= 22
  ing.to_port >= 22
}

sensitive_ingress(ing) if {
  ing.protocol == "tcp"
  ing.from_port <= 3389
  ing.to_port >= 3389
}

# Deny if any ingress is from the internet (IPv4) to sensitive ports/all
deny contains msg if {
  rc := resource_changes_by_type["aws_security_group"][_]
  sg := after(rc)
  ing := sg.ingress[_]

  ing.cidr_blocks[_] == "0.0.0.0/0"
  sensitive_ingress(ing)

  msg := sprintf("SC-7: Security Group %q has broad IPv4 ingress from the internet (SSH/RDP/all).", [sg.name])
}

# Deny if any ingress is from the internet (IPv6) to sensitive ports/all
deny contains msg if {
  rc := resource_changes_by_type["aws_security_group"][_]
  sg := after(rc)
  ing := sg.ingress[_]

  ing.ipv6_cidr_blocks[_] == "::/0"
  sensitive_ingress(ing)

  msg := sprintf("SC-7: Security Group %q has broad IPv6 ingress from the internet (SSH/RDP/all).", [sg.name])
}
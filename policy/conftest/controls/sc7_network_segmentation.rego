package main

# Disallow SG ingress from 0.0.0.0/0 to sensitive ports (22, 3389) or all ports
deny[msg] {
  rc := resource_changes_by_type("aws_security_group")[_]
  sg := after(rc)
  ing := sg.ingress[_]

  # any source open to world
  (ing.cidr_blocks[_] == "0.0.0.0/0") or (ing.ipv6_cidr_blocks[_] == "::/0")

  # sensitive ports or all (-1) / wide range
  open_ssh := ing.from_port <= 22; ing.to_port >= 22; ing.protocol == "tcp"
  open_rdp := ing.from_port <= 3389; ing.to_port >= 3389; ing.protocol == "tcp"
  open_all := ing.protocol == "-1"

  (open_ssh or open_rdp or open_all)

  msg := sprintf("SC-7: Security Group %q has broad ingress from the internet (rule may allow SSH/RDP/all).", [sg.name])
}



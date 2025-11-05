package main

############################
# Helpers
############################

# Is this ingress "sensitive"? (all protocols, or SSH/RDP on TCP)
sensitive_ingress(ing) if {
  ing.protocol == "-1"
}
sensitive_ingress(ing) if {
  ing.protocol == "tcp"
  is_number(ing.from_port)
  is_number(ing.to_port)
  ing.from_port <= 22
  ing.to_port >= 22
}
sensitive_ingress(ing) if {
  ing.protocol == "tcp"
  is_number(ing.from_port)
  is_number(ing.to_port)
  ing.from_port <= 3389
  ing.to_port >= 3389
}

# Public IPv4?
public_ipv4(ing) if {
  ing.cidr_blocks
  ing.cidr_blocks[_] == "0.0.0.0/0"
}

# Public IPv6?
public_ipv6(ing) if {
  ing.ipv6_cidr_blocks
  ing.ipv6_cidr_blocks[_] == "::/0"
}

# --- NEW: OR helper (two rule bodies) ---
public_any(ing) if { public_ipv4(ing) }
public_any(ing) if { public_ipv6(ing) }

############################
# Inline ingress on aws_security_group
############################

deny contains msg if {
  rc := resource_changes_by_type("aws_security_group")[_]
  sg := after(rc)
  sg.ingress
  ing := sg.ingress[_]

  sensitive_ingress(ing)
  public_any(ing)                          # <-- replaced (A or B)

  name := sg.name
  msg := sprintf("SC-7: Security Group %q has public ingress (SSH/RDP/all).", [name])
}

############################
# Standalone aws_security_group_rule (type = ingress)
############################

deny contains msg if {
  rc := resource_changes_by_type("aws_security_group_rule")[_]
  r := after(rc)
  r.type == "ingress"

  # Build a pseudo-ing object for helpers
  ing := {
    "protocol": r.protocol,
    "from_port": r.from_port,
    "to_port": r.to_port,
    "cidr_blocks": r.cidr_blocks,
    "ipv6_cidr_blocks": r.ipv6_cidr_blocks
  }

  sensitive_ingress(ing)
  public_any(ing)                          # <-- replaced (A or B)

  id := r.security_group_id
  msg := sprintf("SC-7: Security Group (id: %v) has public ingress rule (SSH/RDP/all).", [id])
}

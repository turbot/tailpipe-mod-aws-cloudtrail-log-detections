locals {
  mitre_attack_v161_ta0004_t1068_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_technique_id = "T1068"
  })
}

benchmark "mitre_attack_v161_ta0004_t1068" {
  title         = "T1068 Exploitation for Privilege Escalation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1068.md")
  children = [
    detection.detect_vpc_security_group_ingress_egress_updates,
  ]

  tags = local.mitre_attack_v161_ta0004_t1068_common_tags
}

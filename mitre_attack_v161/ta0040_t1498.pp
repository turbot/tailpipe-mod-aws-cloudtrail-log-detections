locals {
  mitre_attack_v161_ta0040_t1498_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1498"
  })
}

benchmark "mitre_attack_v161_ta0040_t1498" {
  title         = "T1498 Network Denial of Service"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1498.md")
  children = [
    detection.detect_vpc_security_group_ingress_egress_updates
  ]

  tags = local.mitre_attack_v161_ta0040_t1498_common_tags
}


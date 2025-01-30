locals {
  mitre_attack_v161_ta0040_t1498_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1498"
  })
}

benchmark "mitre_attack_v161_ta0040_t1498" {
  title         = "T1498 Network Denial of Service"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1498.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1498_001
  ]

  tags = local.mitre_attack_v161_ta0040_t1498_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1498_001" {
  title         = "T1498.001 Network Denial of Service: Direct Network Flood"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1498_001.md")
  children = [
    detection.ec2_instance_launched_with_public_ip,
    detection.vpc_security_group_ingress_egress_rule_updated,
  ]

  tags = merge(local.mitre_attack_v161_ta0040_t1498_common_tags, {
    mitre_attack_technique_id = "T1498.001"
  })
}


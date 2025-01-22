locals {
  mitre_attack_v161_ta0040_t1531_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1531"
  })
}

benchmark "mitre_attack_v161_ta0040_t1531" {
  title         = "T1531 Account Access Removal"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1531.md")
  children = [
    detection.route53_domain_transferred,
    detection.route53_domain_transfer_lock_disabled
  ]

  tags = local.mitre_attack_v161_ta0040_t1531_common_tags
}


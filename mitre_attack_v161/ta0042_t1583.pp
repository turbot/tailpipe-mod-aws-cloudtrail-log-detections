locals {
  mitre_attack_v161_ta0042_t1583_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1583"
  })
}

benchmark "mitre_attack_v161_ta0042_t1583" {
  title         = "T1583 Acquire Infrastructure"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0042_t1583.md")
  children = [
    detection.vpc_created,
  ]

  tags = local.mitre_attack_v161_ta0042_t1583_common_tags
}

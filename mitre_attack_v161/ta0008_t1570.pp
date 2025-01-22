locals {
  mitre_attack_v161_ta0008_t1570_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_technique_id = "T1570"
  })
}

benchmark "mitre_attack_v161_ta0008_t1570" {
  title         = "T1570 Lateral Tool Transfer"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1570.md")
  children = []

  tags = local.mitre_attack_v161_ta0008_t1570_common_tags
}


locals {
  mitre_attack_v161_ta0009_t1005_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_technique_id = "T1005"
  })
}

benchmark "mitre_attack_v161_ta0009_t1005" {
  title         = "T1005 Data from Local System"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1005.md")
  children = []

  tags = local.mitre_attack_v161_ta0009_t1005_common_tags
}


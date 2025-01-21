locals {
  mitre_attack_v161_ta0040_t1484_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1484"
  })
}

benchmark "mitre_attack_v161_ta0040_t1484" {
  title = "T1484 Domain or Tenant Policy Modification"
  type  = "detection"
  # documentation = file("./mitre_attack_v161/docs/ta0040_t1484.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1484_001,
    benchmark.mitre_attack_v161_ta0040_t1484_002,
  ]

  tags = local.mitre_attack_v161_ta0040_t1484_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1484_001" {
  title = "T1484.001 Domain Policy Modification"
  type  = "detection"
  # documentation = file("./mitre_attack_v161/docs/ta0040_t1484_001.md")
  children = [
    detection.iam_role_inline_policy_created,
  ]


  tags = merge(local.mitre_attack_v161_ta0040_t1484_common_tags, {
    mitre_technique_id = "T1484.001"
  })
}

benchmark "mitre_attack_v161_ta0040_t1484_002" {
  title = "T1484.002 Group Policy Modification"
  type  = "detection"
  # documentation = file("./mitre_attack_v161/docs/ta0040_t1484_002.md")
  children = []

  tags = merge(local.mitre_attack_v161_ta0040_t1484_common_tags, {
    mitre_technique_id = "T1484.002"
  })
}

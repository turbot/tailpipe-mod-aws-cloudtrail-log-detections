locals {
  mitre_attack_v161_ta0008_t1550_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_attack_technique_id = "T1550"
  })
}

benchmark "mitre_attack_v161_ta0008_t1550" {
  title         = "T1550 Use Alternate Authentication Material"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1550.md")
  children = [
    benchmark.mitre_attack_v161_ta0008_t1550_001
  ]

  tags = local.mitre_attack_v161_ta0008_t1550_common_tags
}

benchmark "mitre_attack_v161_ta0008_t1550_001" {
  title         = "T1550.001 Application Access Token"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1550_001.md")
  children = [
    detection.iam_access_key_created
  ]

  tags = merge(local.mitre_attack_v161_ta0008_t1550_common_tags, {
    mitre_attack_technique_id = "T1550.001"
  })
}

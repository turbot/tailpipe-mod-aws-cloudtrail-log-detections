locals {
  mitre_attack_v161_ta0008_t1550_001_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_technique_id = "T1550.001"
  })
}

benchmark "mitre_attack_v161_ta0008_t1550_001" {
  title         = "T1550.001 Application Access Token"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1550_001.md")
  children = [
    detection.detect_iam_access_key_creations
  ]

  tags = local.mitre_attack_v161_ta0008_t1550_001_common_tags
}


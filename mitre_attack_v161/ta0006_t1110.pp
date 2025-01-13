locals {
  mitre_attack_v161_ta0006_t1110_common_tags = merge(local.mitre_attack_v161_ta0006_common_tags, {
    mitre_technique_id = "T1110"
  })
}

benchmark "mitre_attack_v161_ta0006_t1110" {
  title         = "T1110 Brute Force"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1110.md")
  children = [
    detection.detect_iam_users_with_password_change
  ]

  tags = local.mitre_attack_v161_ta0006_t1110_common_tags
}


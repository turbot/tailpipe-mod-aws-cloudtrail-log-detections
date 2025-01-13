locals {
  mitre_attack_v161_ta0003_t1136_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1136"
  })
}

benchmark "mitre_attack_v161_ta0003_t1136" {
  title         = "T1136 Create Account"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1136.md")
  children = [
    detection.detect_iam_entities_created_without_cloudformation,
    detection.detect_iam_user_creations
  ]

  tags = local.mitre_attack_v161_ta0003_t1136_common_tags
}

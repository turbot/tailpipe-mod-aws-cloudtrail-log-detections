locals {
  mitre_attack_v161_ta0004_t1098_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0004_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1098.md")
  children = [
    detection.detect_inline_policies_attached_to_iam_users,
    detection.detect_managed_policies_attached_to_iam_users,
    detection.detect_managed_policies_attached_to_iam_roles,
  ]

  tags = local.mitre_attack_v161_ta0004_t1098_common_tags
}

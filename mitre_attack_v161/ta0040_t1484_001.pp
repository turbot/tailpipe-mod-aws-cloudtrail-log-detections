locals {
  mitre_attack_v161_ta0040_t1484_001_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1484.001"
  })
}

benchmark "mitre_attack_v161_ta0040_t1484_001" {
  title         = "T1484.001 Domain Policy Modification"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1484_001.md")
  children = [
    detection.detect_admin_access_granted_to_iam_roles,
    detection.detect_admin_access_granted_to_iam_users,
    detection.detect_iam_role_inline_policy_creations,
    detection.detect_public_access_granted_to_iam_groups,
    detection.detect_public_access_granted_to_iam_roles,
    detection.detect_public_access_granted_to_iam_users,
  ]

  tags = local.mitre_attack_v161_ta0040_t1484_001_common_tags
}



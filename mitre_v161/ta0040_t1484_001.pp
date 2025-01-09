locals {
  mitre_v161_ta0040_t1484_001_common_tags = merge(local.mitre_v161_ta0040_common_tags, {
    mitre_technique_id = "T1484.001"
  })
}

benchmark "mitre_v161_ta0040_t1484_001" {
  title         = "T1484.001 Domain Policy Modification"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0040_t1484_001.md")
  children = [
    detection.cloudtrail_logs_detect_admin_access_granted_to_iam_roles,
    detection.cloudtrail_logs_detect_admin_access_granted_to_iam_users,
    detection.cloudtrail_logs_detect_iam_role_inline_policy_creations,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_groups,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_roles,
    detection.cloudtrail_logs_detect_public_access_granted_to_iam_users,
  ]

  tags = local.mitre_v161_ta0040_t1484_001_common_tags
}



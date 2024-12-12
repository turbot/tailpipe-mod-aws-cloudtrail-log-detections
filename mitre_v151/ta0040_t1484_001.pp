locals {
  mitre_v151_ta0040_t1484_001_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1484.001"
  })
}

benchmark "mitre_v151_ta0040_t1484_001" {
  title         = "T1484.001 Domain Policy Modification"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1484_001.md")
  children = [
    detection.cloudtrail_logs_detect_iam_role_policy_updates,
    detection.cloudtrail_logs_detect_iam_user_policy_updates
  ]

  tags = local.mitre_v151_ta0040_t1484_001_common_tags
}



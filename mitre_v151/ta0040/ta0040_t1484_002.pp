locals {
  mitre_v151_ta0040_t1484_002_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1484.002"
  })
}

benchmark "mitre_v151_ta0040_t1484_002" {
  title         = "T1484.002 Group Policy Modification"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1484_002.md")
  children = [
    detection.cloudtrail_logs_detect_iam_group_policy_updates
  ]

  tags = local.mitre_v151_ta0040_t1484_002_common_tags
}

locals {
  mitre_v151_ta0004_t1098_common_tags = merge(local.mitre_v151_ta0004_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_v151_ta0004_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0004_t1098.md")
  children = [
    detection.cloudtrail_logs_detect_inline_policy_added,
    detection.cloudtrail_logs_detect_managed_policy_attachment,
  ]

  tags = local.mitre_v151_ta0004_t1098_common_tags
}

locals {
  mitre_v151_ta0004_t1078_common_tags = merge(local.mitre_v151_ta0004_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v151_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0004_t1078.md")
  children = [
    detection.cloudtrail_logs_detect_iam_users_attached_to_admin_groups,
  ]

  tags = local.mitre_v151_ta0004_t1078_common_tags
}

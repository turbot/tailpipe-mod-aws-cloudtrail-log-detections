locals {
  mitre_v161_ta0003_t1098_common_tags = merge(local.mitre_v161_ta0003_common_tags, {
    mitre_technique_id = "T1098"
  })
}

benchmark "mitre_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1098.md")
  children = [
    detection.cloudtrail_logs_detect_iam_users_with_console_access_enabled,
    detection.cloudtrail_logs_detect_rds_db_instance_master_password_updates,
  ]

  tags = local.mitre_v161_ta0003_t1098_common_tags
}

locals {
  mitre_v151_ta0008_t1210_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1210"
  })
}

benchmark "mitre_v151_ta0008_t1210" {
  title         = "T1210 Exploitation of Remote Services"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1210.md")
  children = [
    detection.cloudtrail_logs_detect_rds_db_instance_disable_iam_authentication_updates,
    detection.cloudtrail_logs_detect_rds_instance_pulicly_accessible,
  ]

  tags = local.mitre_v151_ta0008_t1210_common_tags
}


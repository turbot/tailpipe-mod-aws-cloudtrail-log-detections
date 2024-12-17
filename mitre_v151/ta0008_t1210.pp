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
    detection.cloudtrail_logs_detect_disabled_iam_authentication_rds_db_instances,
    detection.cloudtrail_logs_detect_publicly_accessible_rds_db_instances,
  ]

  tags = local.mitre_v151_ta0008_t1210_common_tags
}


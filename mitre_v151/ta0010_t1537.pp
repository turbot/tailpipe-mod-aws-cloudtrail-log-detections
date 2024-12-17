locals {
  mitre_v151_ta0010_t1537_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1537"
  })
}

benchmark "mitre_v151_ta0010_t1537" {
  title         = "T1537 Transfer Data to Cloud Account"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1537.md")
  children = [
    detection.cloudtrail_logs_detect_rds_db_manual_snapshot_creations
  ]

  tags = local.mitre_v151_ta0010_t1537_common_tags
}

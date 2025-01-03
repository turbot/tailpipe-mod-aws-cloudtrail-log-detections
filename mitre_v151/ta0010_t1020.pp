locals {
  mitre_v151_ta0010_t1020_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1020"
  })
}

benchmark "mitre_v151_ta0010_t1020" {
  title         = "T1020 Automated Exfiltration"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1020.md")
  children = [
    detection.cloudtrail_logs_detect_rds_db_instances_public_restore,
    detection.cloudtrail_logs_detect_public_access_granted_to_nacl,
  ]

  tags = local.mitre_v151_ta0010_t1020_common_tags
}

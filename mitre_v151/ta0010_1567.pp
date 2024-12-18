locals {
  mitre_v151_ta0010_t1567_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1567"
  })
}

benchmark "mitre_v151_ta0010_t1567" {
  title         = "T1567 Exfiltration Over Web Service"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1567.md")
  children = [
    benchmark.mitre_v151_ta0010_t1567_001
  ]

  tags = local.mitre_v151_ta0010_t1567_common_tags
}

benchmark "mitre_v151_ta0010_t1567_001" {
  title         = "T1567.001 Exfiltration to Code Repository"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1567_001.md")
  children = [
    detection.cloudtrail_logs_detect_public_access_granted_to_codebuild_projects,
    detection.cloudtrail_logs_detect_rds_db_manual_snapshot_creations
  ]

  tags = merge(local.mitre_v151_ta0010_t1567_common_tags, {
    mitre_technique_id = "T1567.001"
  })
}
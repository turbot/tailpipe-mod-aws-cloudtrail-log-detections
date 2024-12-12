locals {
  mitre_v151_ta0008_t1570_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1570"
  })
}

benchmark "mitre_v151_ta0008_t1570" {
  title         = "T1570 Lateral Tool Transfer"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1570.md")
  children = [
    detection.cloudtrail_logs_detect_s3_tool_uploads
  ]

  tags = local.mitre_v151_ta0008_t1570_common_tags
}


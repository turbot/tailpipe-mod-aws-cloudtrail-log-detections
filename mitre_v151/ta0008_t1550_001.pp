locals {
  mitre_v151_ta0008_t1550_001_common_tags = merge(local.mitre_v151_ta0008_common_tags, {
    mitre_technique_id = "T1550.001"
  })
}

benchmark "mitre_v151_ta0008_t1550_001" {
  title         = "T1550.001 Application Access Token"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0008_t1550_001.md")
  children = [
    detection.cloudtrail_logs_detect_iam_access_key_creations
  ]

  tags = local.mitre_v151_ta0008_t1550_001_common_tags
}


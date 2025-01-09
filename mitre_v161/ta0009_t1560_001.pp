locals {
  mitre_v161_ta0009_t1560_001_common_tags = merge(local.mitre_v161_ta0009_common_tags, {
    mitre_technique_id = "T1560.001"
  })
}

benchmark "mitre_v161_ta0009_t1560_001" {
  title         = "T1560.001 Archive Collected Data"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0009_t1560_001.md")
  children = [
    detection.cloudtrail_logs_detect_s3_data_archiving
  ]

  tags = local.mitre_v161_ta0009_t1560_001_common_tags
}


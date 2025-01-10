locals {
  mitre_v161_ta0002_t1651_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1651"
  })
}

benchmark "mitre_v161_ta0002_t1651" {
  title         = "T1651 Cloud Administration Command"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1651.md")
  children = [
    detection.cloudtrail_logs_detect_ssm_documents_with_unauthorized_data_access_from_local_systems,
    detection.cloudtrail_logs_detect_ssm_documents_with_unauthorized_input_captures,
  ]

  tags = local.mitre_v161_ta0002_t1651_common_tags
}

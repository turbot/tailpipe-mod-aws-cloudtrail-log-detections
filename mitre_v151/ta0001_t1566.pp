locals {
  mitre_v151_ta0001_t1566_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1566"
  })
}

benchmark "mitre_v151_ta0001_t1566" {
  title         = "T1566 Phishing"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001_t1566.md")
  children = [
    detection.cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes,
    detection.cloudtrail_logs_detect_ses_sending_rate_limit_increase,
    detection.cloudtrail_logs_detect_ses_sending_enabled,
  ]

  tags = local.mitre_v151_ta0001_t1566_common_tags
}

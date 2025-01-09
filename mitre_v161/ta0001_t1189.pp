locals {
  mitre_v161_ta0001_t1189_common_tags = merge(local.mitre_v161_ta0001_common_tags, {
    mitre_technique_id = "T1189"
  })
}

benchmark "mitre_v161_ta0001_t1189" {
  title         = "T1189 Drive-by Compromise"
  type          = "detection"
  # documentation = file("./mitre_v161/docs/ta0001_t1189.md")
  children = [
    detection.cloudtrail_logs_detect_public_access_granted_to_s3_buckets,
    detection.cloudtrail_logs_detect_codebuild_projects_with_environment_variable_changes,
    detection.cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role,
  ]

  tags = local.mitre_v161_ta0001_t1189_common_tags
}

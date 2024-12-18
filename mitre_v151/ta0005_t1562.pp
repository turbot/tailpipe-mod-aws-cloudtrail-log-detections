locals {
  mitre_v151_ta0005_t1562_common_tags = merge(local.mitre_v151_ta0005_common_tags, {
    mitre_technique_id = "T1562"
  })
}

benchmark "mitre_v151_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1562.md")
  children = [
    benchmark.mitre_v151_ta0005_t1562_001
  ]

  tags = local.mitre_v151_ta0005_t1562_common_tags
}

benchmark "mitre_v151_ta0005_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1562_001.md")
  children = [
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_lambda_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_encryption_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_kms_key_updated,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_bucket_modified,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_global_service_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trail_deletions,
    detection.cloudtrail_logs_detect_waf_web_acl_deletions,
    detection.cloudtrail_logs_detect_disabled_eventbridge_rules,
    detection.cloudtrail_logs_detect_guardduty_detector_deletions,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_logging_disabled,
    detection.cloudtrail_logs_detect_vpcs_with_classic_link_enabled,
    detection.cloudtrail_logs_detect_codebuild_projects_with_source_repository_changes,
    detection.cloudtrail_logs_detect_config_service_rule_deletions,
    detection.cloudtrail_logs_detect_config_service_delivery_channel_deletions,
    detection.cloudtrail_logs_detect_config_service_configuration_recorder_deletions,
  ]

  tags = merge(local.mitre_v151_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.001"
  })
}

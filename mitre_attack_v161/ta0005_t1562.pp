locals {
  mitre_attack_v161_ta0005_t1562_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_technique_id = "T1562"
  })
}

benchmark "mitre_attack_v161_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562.md")
  children = [
    benchmark.mitre_attack_v161_ta0005_t1562_001
  ]

  tags = local.mitre_attack_v161_ta0005_t1562_common_tags
}

benchmark "mitre_attack_v161_ta0005_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_001.md")
  children = [
    detection.detect_cloudfront_distributions_with_logging_disabled,
    detection.detect_cloudtrail_trails_with_encryption_disabled,
    detection.detect_cloudtrail_trails_with_global_service_logging_disabled,
    detection.detect_cloudtrail_trails_with_kms_key_updated,
    detection.detect_cloudtrail_trails_with_lambda_logging_disabled,
    detection.detect_cloudtrail_trails_with_s3_logging_bucket_modified,
    detection.detect_cloudtrail_trails_with_s3_logging_disabled,
    detection.detect_codebuild_projects_with_source_repository_updates,
    detection.detect_config_rule_deletions,
    detection.detect_config_configuration_recorders_with_recording_stopped,
    detection.detect_eventbridge_rules_disabled,
    detection.detect_guardduty_detector_deletions,
    detection.detect_vpcs_with_classic_link_enabled,
    detection.waf_web_acl_disassociated_from_cloudfront_distribution,
    detection.waf_web_acl_disassociated_from_alb,
    detection.detect_sns_topics_with_encryption_at_rest_disabled,
    detection.detect_vpc_creations,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.001"
  })
}

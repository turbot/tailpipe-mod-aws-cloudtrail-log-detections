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
    detection.cloudfront_distributions_logging_disabled,
    detection.cloudtrail_trails_encryption_disabled,
    detection.cloudtrail_trails_global_service_logging_disabled,
    detection.cloudtrail_trails_kms_key_updated,
    detection.cloudtrail_trails_lambda_logging_disabled,
    detection.cloudtrail_trails_s3_logging_bucket_modified,
    detection.cloudtrail_trails_s3_logging_disabled,
    detection.codebuild_projects_source_repository_updated,
    detection.config_rules_deleted,
    detection.config_configuration_recorders_recording_stopped,
    detection.eventbridge_rules_disabled,
    detection.detect_guardduty_detector_deletions,
    detection.detect_vpcs_with_classic_link_enabled,
    detection.detect_waf_acl_disassociation_from_cloudfront_distributions,
    detection.detect_waf_acl_disassociation_from_alb,
    detection.detect_sns_topics_with_encryption_at_rest_disabled,
    detection.detect_vpc_creations,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.001"
  })
}

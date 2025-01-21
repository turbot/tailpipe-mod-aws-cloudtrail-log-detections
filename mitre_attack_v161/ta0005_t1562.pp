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
    benchmark.mitre_attack_v161_ta0005_t1562_001,
    benchmark.mitre_attack_v161_ta0005_t1562_002,
    benchmark.mitre_attack_v161_ta0005_t1562_004,
  ]

  tags = local.mitre_attack_v161_ta0005_t1562_common_tags
}

benchmark "mitre_attack_v161_ta0005_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_001.md")
  children = [
    detection.cloudtrail_trail_encryption_disabled,
    detection.cloudtrail_trail_global_service_logging_disabled,
    detection.cloudtrail_trail_kms_key_updated,
    detection.cloudtrail_trail_lambda_logging_disabled,
    detection.cloudtrail_trail_s3_logging_bucket_modified,
    detection.cloudtrail_trail_s3_logging_disabled,
    detection.codebuild_project_source_repository_updated,
    detection.config_rule_deleted,
    detection.config_configuration_recorder_stopped,
    detection.eventbridge_rule_disabled,
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

benchmark "mitre_attack_v161_ta0005_t1562_002" {
  title         = "T1562.002 Disable Windows Event Logging"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_002.md")
  children = [
    detection.cloudfront_distribution_logging_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.002"
  })
}

benchmark "mitre_attack_v161_ta0005_t1562_004" {
  title         = "T1562.004 Disable or Modify System Firewall"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_004.md")
  children = [
    detection.cloudfront_distribution_geo_restriction_disabled,
    detection.cloudfront_distribution_default_certificate_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.004"
  })
}
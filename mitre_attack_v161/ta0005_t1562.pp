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
    benchmark.mitre_attack_v161_ta0005_t1562_008,
  ]

  tags = local.mitre_attack_v161_ta0005_t1562_common_tags
}

benchmark "mitre_attack_v161_ta0005_t1562_001" {
  title         = "T1562.001 Impair Defenses: Disable or Modify Tools"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_001.md")
  children = [
    detection.cloudtrail_trail_global_service_logging_disabled,
    detection.cloudtrail_trail_kms_key_updated,
    detection.cloudtrail_trail_logging_stopped,
    detection.cloudtrail_trail_s3_logging_bucket_updated,
    detection.codebuild_project_source_repository_updated,
    detection.config_configuration_recorder_stopped,
    detection.config_rule_deleted,
    detection.eventbridge_rule_disabled,
    detection.guardduty_detector_deleted,
    detection.vpc_classic_link_enabled,
    detection.vpc_created,
    detection.waf_web_acl_disassociated_from_cloudfront_distribution,
    detection.waf_web_acl_disassociated_from_elb_application_load_balancer,
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
    detection.cloudfront_distribution_default_certificate_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.004"
  })
}

benchmark "mitre_attack_v161_ta0005_t1562_008" {
  title         = "T1562.008 Impair Defenses: Disable or Modify Cloud Logs"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1562_008.md")
  children = [
    detection.cloudwatch_log_group_created_with_encryption_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.008"
  })
}
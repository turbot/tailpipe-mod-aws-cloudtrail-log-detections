locals {
  mitre_v161_ta0001_t1659_common_tags = merge(local.mitre_v161_ta0001_common_tags, {
    mitre_technique_id = "T1659"
  })
}

benchmark "mitre_v161_ta0001_t1659" {
  title         = "T1659 Content Injection"
  type          = "detection"
  # documentation = file("./mitre_v161/docs/ta0001_t1659.md")
  children = [
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_default_certificates_disabled,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_failover_criteria_modified,
    detection.cloudtrail_logs_detect_cloudfront_distributions_with_geo_restriction_disabled,
    detection.cloudtrail_logs_detect_public_access_granted_to_cloudfront_distribution_origins,
    detection.cloudtrail_logs_detect_waf_acl_disassociation_from_alb,
    detection.cloudtrail_logs_detect_waf_acl_disassociation_from_cloudfront_distributions,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes,
    detection.cloudtrail_logs_detect_cloudwatch_log_retention_period_changes,
    detection.cloudtrail_logs_detect_cloudwatch_subscription_filter_changes,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_action_changes,
  ]

  tags = local.mitre_v161_ta0001_t1659_common_tags
}

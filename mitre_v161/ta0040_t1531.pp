locals {
  mitre_v161_ta0040_t1531_common_tags = merge(local.mitre_v161_ta0040_common_tags, {
    mitre_technique_id = "T1531"
  })
}

benchmark "mitre_v161_ta0040_t1531" {
  title         = "T1531 Account Access Removal"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0040_t1531.md")
  children = [
    detection.cloudtrail_logs_detect_route53_domain_transfers,
    detection.cloudtrail_logs_detect_route53_domains_with_transfer_lock_disabled,
    detection.cloudtrail_logs_detect_sns_topics_subscription_deletions
  ]

  tags = local.mitre_v161_ta0040_t1531_common_tags
}


locals {
  mitre_v151_ta0040_t1531_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1531"
  })
}

benchmark "mitre_v151_ta0040_t1531" {
  title         = "T1531 Account Access Removal"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1531.md")
  children = [
    detection.cloudtrail_logs_detect_route53_domain_transfered_to_another_accounts,
    detection.cloudtrail_logs_detect_transfer_lock_disabled_route53_domains
  ]

  tags = local.mitre_v151_ta0040_t1531_common_tags
}


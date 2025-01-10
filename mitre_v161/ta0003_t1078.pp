locals {
  mitre_v161_ta0003_t1078_common_tags = merge(local.mitre_v161_ta0003_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_v161_ta0003_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0003_t1078.md")
  children = [
    detection.cloudtrail_logs_detect_route53_vpc_associations_with_hosted_zones,
    detection.cloudtrail_logs_detect_vpcs_with_classic_link_enabled
  ]

  tags = local.mitre_v161_ta0003_t1078_common_tags
}

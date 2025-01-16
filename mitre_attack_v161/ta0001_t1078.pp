locals {
  mitre_attack_v161_ta0001_t1078_common_tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001_t1078.md")
  children = [
    detection.detect_iam_root_user_console_logins,
    detection.detect_route53_vpc_associations_with_hosted_zones,
    detection.detect_vpcs_with_classic_link_enabled,
  ]

  tags = local.mitre_attack_v161_ta0001_t1078_common_tags
}

locals {
  mitre_v151_ta0005_t1070_common_tags = merge(local.mitre_v151_ta0005_common_tags, {
    mitre_technique_id = "T1070"
  })
}

benchmark "mitre_v151_ta0005_t1070" {
  title         = "T1070 Indicator Removal"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005_t1070.md")
  children = [
    detection.cloudtrail_logs_detect_security_group_ipv4_allow_all,
    detection.cloudtrail_logs_detect_security_group_ipv6_allow_all,
    detection.cloudtrail_logs_detect_s3_bucket_policy_public,
    detection.cloudtrail_logs_detect_kms_key_deletions
  ]

  tags = local.mitre_v151_ta0005_t1070_common_tags
}


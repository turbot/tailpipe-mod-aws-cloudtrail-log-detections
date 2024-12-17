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
    detection.cloudtrail_logs_detect_public_access_granted_to_s3_buckets,
    detection.cloudtrail_logs_detect_kms_key_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_route_deletions,
    detection.cloudtrail_logs_detect_vpc_route_table_route_disassociations,
    detection.cloudtrail_logs_detect_vpc_route_table_replace_associations,
    detection.cloudtrail_logs_detect_vpc_deletions,
    detection.cloudtrail_logs_detect_vpc_peering_connection_deletions,
  ]

  tags = local.mitre_v151_ta0005_t1070_common_tags
}


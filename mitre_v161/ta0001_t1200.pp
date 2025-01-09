locals {
  mitre_v161_ta0001_t1200_common_tags = merge(local.mitre_v161_ta0001_common_tags, {
    mitre_technique_id = "T1200"
  })
}

benchmark "mitre_v161_ta0001_t1200" {
  title         = "T1200 Hardware Additions"
  type          = "detection"
  # documentation = file("./mitre_v161/docs/ta0001_t1200.md")
  children = [
    detection.cloudtrail_logs_detect_vpc_route_table_replace_associations,
    detection.cloudtrail_logs_detect_vpc_route_table_route_disassociations,
    detection.cloudtrail_logs_detect_vpc_security_group_ingress_egress_updates,
    detection.cloudtrail_logs_detect_internet_gateways_added_to_public_route_tables,
  ]

  tags = local.mitre_v161_ta0001_t1200_common_tags
}

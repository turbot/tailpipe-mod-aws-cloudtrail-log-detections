locals {
  mitre_attack_v161_ta0005_t1070_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_attack_technique_id = "T1070"
  })
}

benchmark "mitre_attack_v161_ta0005_t1070" {
  title         = "T1070 Indicator Removal"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1070.md")
  children = [
    detection.sqs_queue_dlq_disabled,
    detection.vpc_deleted,
    detection.vpc_flow_log_deleted,
    detection.vpc_peering_connection_deleted,
    detection.vpc_route_table_association_replaced,
    detection.vpc_route_table_deleted,
    detection.vpc_route_table_route_deleted,
    detection.vpc_route_table_route_disassociated,
    detection.vpc_security_group_deleted,
  ]

  tags = local.mitre_attack_v161_ta0005_t1070_common_tags
}


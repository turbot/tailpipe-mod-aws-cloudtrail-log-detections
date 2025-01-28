locals {
  mitre_attack_v161_ta0040_t1565_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1565"
  })
}

benchmark "mitre_attack_v161_ta0040_t1565" {
  title         = "T1565 Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1565.md")
  children = [
    benchmark.mitre_attack_v161_ta0040_t1565_003
  ]

  tags = local.mitre_attack_v161_ta0040_t1565_common_tags
}

benchmark "mitre_attack_v161_ta0040_t1565_003" {
  title         = "T1565.003 Data Manipulation: Runtime Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1565_003.md")
  children = [
    detection.vpc_deleted,
    detection.vpc_peering_connection_deleted,
    detection.vpc_route_table_association_replaced,
    detection.vpc_route_table_deleted,
    detection.vpc_route_table_route_deleted,
    detection.vpc_route_table_route_disassociated,
  ]

  tags = local.mitre_attack_v161_ta0040_t1565_common_tags
}

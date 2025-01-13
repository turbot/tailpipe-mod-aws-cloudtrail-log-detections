locals {
  mitre_attack_v161_ta0040_t1565_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1565"
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
  title         = "T1565.003 Runtime Data Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1565_003.md")
  children = [
    detection.detect_vpc_deletions,
    detection.detect_vpc_peering_connection_deletions,
    detection.detect_vpc_route_table_deletions,
    detection.detect_vpc_route_table_replace_associations,
    detection.detect_vpc_route_table_route_deletions,
    detection.detect_vpc_route_table_route_disassociations,
  ]

  tags = local.mitre_attack_v161_ta0040_t1565_common_tags
}

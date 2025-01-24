locals {
  mitre_attack_v161_ta0009_t1560_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_technique_id = "T1560"
  })
}

benchmark "mitre_attack_v161_ta0009_t1560" {
  title         = "T1560 Archive Collected Data"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1560.md")
  children = [
    benchmark.mitre_attack_v161_ta0009_t1560_001
  ]

  tags = local.mitre_attack_v161_ta0009_t1560_common_tags
}

benchmark "mitre_attack_v161_ta0009_t1560_001" {
  title         = "T1560.001 Archive Collected Data: Archive via Utility"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1560_001.md")
  children = [
    detection.s3_data_archived
  ]

  tags = merge(local.mitre_attack_v161_ta0009_t1560_common_tags, {
    mitre_technique_id = "T1560.001"
  })
}


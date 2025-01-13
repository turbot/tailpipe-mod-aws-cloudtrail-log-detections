locals {
  mitre_attack_v161_ta0009_t1560_001_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_technique_id = "T1560.001"
  })
}

benchmark "mitre_attack_v161_ta0009_t1560_001" {
  title         = "T1560.001 Archive Collected Data"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1560_001.md")
  children = [
    detection.detect_s3_data_archiving
  ]

  tags = local.mitre_attack_v161_ta0009_t1560_001_common_tags
}


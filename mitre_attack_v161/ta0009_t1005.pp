locals {
  mitre_attack_v161_ta0009_t1005_common_tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    mitre_technique_id = "T1005"
  })
}

benchmark "mitre_attack_v161_ta0009_t1005" {
  title         = "T1005 Data from Local System"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009_t1005.md")
  children = [
    detection.detect_ssm_documents_with_unauthorized_data_access_from_local_systems
  ]

  tags = local.mitre_attack_v161_ta0009_t1005_common_tags
}


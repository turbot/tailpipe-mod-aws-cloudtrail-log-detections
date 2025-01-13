locals {
  mitre_attack_v161_ta0002_t1651_common_tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    mitre_technique_id = "T1651"
  })
}

benchmark "mitre_attack_v161_ta0002_t1651" {
  title         = "T1651 Cloud Administration Command"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002_t1651.md")
  children = [
    detection.detect_ssm_documents_with_unauthorized_data_access_from_local_systems,
    detection.detect_ssm_documents_with_unauthorized_input_captures,
  ]

  tags = local.mitre_attack_v161_ta0002_t1651_common_tags
}

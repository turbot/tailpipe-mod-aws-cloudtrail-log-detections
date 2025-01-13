locals {
  mitre_attack_v161_ta0008_t1210_common_tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    mitre_technique_id = "T1210"
  })
}

benchmark "mitre_attack_v161_ta0008_t1210" {
  title         = "T1210 Exploitation of Remote Services"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008_t1210.md")
  children = [
    detection.detect_rds_db_instances_with_iam_authentication_disabled,
    detection.detect_public_access_granted_to_rds_db_instances,
  ]

  tags = local.mitre_attack_v161_ta0008_t1210_common_tags
}


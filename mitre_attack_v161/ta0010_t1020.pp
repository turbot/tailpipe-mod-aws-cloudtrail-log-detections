locals {
  mitre_attack_v161_ta0010_t1020_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_technique_id = "T1020"
  })
}

benchmark "mitre_attack_v161_ta0010_t1020" {
  title         = "T1020 Automated Exfiltration"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1020.md")
  children = [
    detection.rds_db_instance_restored_from_public_snapshot,
    detection.vpc_nacl_rule_updated_with_allow_public_access,
  ]

  tags = local.mitre_attack_v161_ta0010_t1020_common_tags
}

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
    detection.rds_db_instance_public_restore,
    detection.detect_public_access_granted_to_vpc_nacl_rules,
  ]

  tags = local.mitre_attack_v161_ta0010_t1020_common_tags
}

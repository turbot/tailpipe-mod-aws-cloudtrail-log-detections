locals {
  mitre_attack_v161_ta0040_t1490_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1490"
  })
}

benchmark "mitre_attack_v161_ta0040_t1490" {
  title         = "T1490 Inhibit System Recovery"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1490.md")
  children = [
    detection.efs_file_system_backup_policy_disabled,
  ]

  tags = local.mitre_attack_v161_ta0040_t1490_common_tags
}

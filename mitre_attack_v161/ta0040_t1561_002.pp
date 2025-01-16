locals {
  mitre_attack_v161_ta0040_t1561_002_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1561.002"
  })
}

benchmark "mitre_attack_v161_ta0040_t1561_002" {
  title         = "T1561.002 Disk Structure Wipe"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1561_002.md")
  children = [
    detection.ebs_volume_detached,
  ]

  tags = local.mitre_attack_v161_ta0040_t1561_002_common_tags
}

locals {
  mitre_attack_v161_ta0040_t1495_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_attack_technique_id = "T1495"
  })
}

benchmark "mitre_attack_v161_ta0040_t1495" {
  title         = "T1495 Firmware Corruption"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1495.md")
  children = [
    detection.ec2_ami_shared_publicly,
  ]

  tags = local.mitre_attack_v161_ta0040_t1495_common_tags
}

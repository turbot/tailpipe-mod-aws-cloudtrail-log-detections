locals {
  mitre_attack_v161_ta0040_t1495_common_tags = merge(local.mitre_attack_v161_ta0040_common_tags, {
    mitre_technique_id = "T1495"
  })
}

benchmark "mitre_attack_v161_ta0040_t1495" {
  title         = "T1495 Firmware Corruption"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0040_t1495.md")
  children = [
    detection.detect_ec2_instances_with_source_dest_check_disabled,
    detection.detect_ec2_amis_with_launch_permission_changes,
  ]

  tags = local.mitre_attack_v161_ta0040_t1495_common_tags
}

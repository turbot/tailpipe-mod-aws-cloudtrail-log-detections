locals {
  mitre_v151_ta0040_t1495_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1495"
  })
}

benchmark "mitre_v151_ta0040_t1495" {
  title         = "T1495 Firmware Corruption"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1495.md")
  children = [
    detection.cloudtrail_logs_detect_ec2_instance_updates
  ]

  tags = local.mitre_v151_ta0040_t1495_common_tags
}

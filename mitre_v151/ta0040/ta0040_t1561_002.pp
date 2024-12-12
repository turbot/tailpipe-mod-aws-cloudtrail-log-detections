locals {
  mitre_v151_ta0040_t1561_002_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1561.002"
  })
}

benchmark "mitre_v151_ta0040_t1561_002" {
  title         = "T1561.002 Disk Structure Wipe"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1561_002.md")
  children = [
    detection.cloudtrail_logs_detect_ebs_volume_updates
  ]

  tags = local.mitre_v151_ta0040_t1561_002_common_tags
}

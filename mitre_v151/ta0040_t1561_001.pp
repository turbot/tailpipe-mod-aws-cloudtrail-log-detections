locals {
  mitre_v151_ta0040_t1561_001_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1561.001"
  })
}

benchmark "mitre_v151_ta0040_t1561_001" {
  title         = "T1561.001 Disk Content Wipe"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1561_001.md")
  children = [
    detection.cloudtrail_logs_detect_ebs_volume_deleted
  ]

  tags = local.mitre_v151_ta0040_t1561_001_common_tags
}


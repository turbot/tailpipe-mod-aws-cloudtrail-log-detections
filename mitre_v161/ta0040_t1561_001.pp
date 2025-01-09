locals {
  mitre_v161_ta0040_t1561_001_common_tags = merge(local.mitre_v161_ta0040_common_tags, {
    mitre_technique_id = "T1561.001"
  })
}

benchmark "mitre_v161_ta0040_t1561_001" {
  title         = "T1561.001 Disk Content Wipe"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0040_t1561_001.md")
  children = []

  tags = local.mitre_v161_ta0040_t1561_001_common_tags
}


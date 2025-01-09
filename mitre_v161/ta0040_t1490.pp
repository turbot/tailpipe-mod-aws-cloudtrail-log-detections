locals {
  mitre_v161_ta0040_t1490_common_tags = merge(local.mitre_v161_ta0040_common_tags, {
    mitre_technique_id = "T1490"
  })
}

benchmark "mitre_v161_ta0040_t1490" {
  title         = "T1490 Inhibit System Recovery"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0040_t1490.md")
  children = [

  ]

  tags = local.mitre_v161_ta0040_t1490_common_tags
}


locals {
  mitre_v161_ta0002_t1204_common_tags = merge(local.mitre_v161_ta0002_common_tags, {
    mitre_technique_id = "T1204"
  })
}

benchmark "mitre_v161_ta0002_t1204" {
  title         = "T1204 User Execution"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002_t1204.md")
  children = []

  tags = local.mitre_v161_ta0002_t1204_common_tags
}

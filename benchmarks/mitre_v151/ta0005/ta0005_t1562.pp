locals {
  mitre_v151_ta0005_t1562_common_tags = merge(local.mitre_v151_ta0005_common_tags, {
    mitre_technique_id = "T1562"
  })
}

benchmark "mitre_v151_ta0005_t1562" {
  title         = "T1562 Impair Defenses"
  //documentation = file("./cis_v130/docs/cis_v130_3.md")
  children = [
    benchmark.mitre_v151_ta0005_t1562_001
  ]

  tags = local.mitre_v151_ta0005_t1562_common_tags
}

benchmark "mitre_v151_ta0005_t1562_001" {
  title         = "T1562.001 Disable or Modify Tools"
  //documentation = file("./cis_v130/docs/cis_v130_3.md")
  children = [
    control.cloudtrail_log_cloudtrail_trail_updates
  ]

  tags = merge(local.mitre_v151_ta0005_t1562_common_tags, {
    mitre_technique_id = "T1562.001"
  })
}

locals {
  mitre_v151_ta0005_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0005"
  })
}

benchmark "mitre_v151_ta0005" {
  title         = "TA0005 Defense Evasion"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0005.md")
  children = [
    benchmark.mitre_v151_ta0005_t1562,
  ]

  tags = merge(local.mitre_v151_ta0005_common_tags, {
    type = "Benchmark"
  })
}

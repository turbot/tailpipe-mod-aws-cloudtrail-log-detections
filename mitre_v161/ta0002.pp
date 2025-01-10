locals {
  mitre_v161_ta0002_common_tags = merge(local.mitre_v161_common_tags, {
    mitre_tactic_id = "TA0002"
  })
}

benchmark "mitre_v161_ta0002" {
  title         = "TA0002 Execution"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0002.md")
  children = [
    benchmark.mitre_v161_ta0002_t1651,
    benchmark.mitre_v161_ta0002_t1059,
    benchmark.mitre_v161_ta0002_t1648,
    benchmark.mitre_v161_ta0002_t1204,
  ]

  tags = merge(local.mitre_v161_ta0002_common_tags, {
    type = "Benchmark"
  })
}

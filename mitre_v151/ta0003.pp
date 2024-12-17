locals {
  mitre_v151_ta0003_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0003"
  })
}

benchmark "mitre_v151_ta0003" {
  title         = "TA0003 Persistence"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0003.md")
  children = [
    benchmark.mitre_v151_ta0003_t1098,
    benchmark.mitre_v151_ta0003_t1136,
    benchmark.mitre_v151_ta0003_t1078,
  ]

  tags = merge(local.mitre_v151_ta0003_common_tags, {
    type = "Benchmark"
  })
}

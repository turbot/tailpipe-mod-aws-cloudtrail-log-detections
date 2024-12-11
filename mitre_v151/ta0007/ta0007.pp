locals {
  mitre_v151_ta0007_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0007"
  })
}

benchmark "mitre_v151_ta0007" {
  title         = "TA0007 Discovery"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0007.md")
  children = [
    benchmark.mitre_v151_ta0007_t1007,
    benchmark.mitre_v151_ta0007_t1016,
    benchmark.mitre_v151_ta0007_t1046,
    benchmark.mitre_v151_ta0007_t1057,
    benchmark.mitre_v151_ta0007_t1083,
    benchmark.mitre_v151_ta0007_t1135,
  ]

  tags = merge(local.mitre_v151_ta0007_common_tags, {
    type = "Benchmark"
  })
}

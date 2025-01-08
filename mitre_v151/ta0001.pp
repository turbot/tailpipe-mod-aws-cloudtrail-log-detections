locals {
  mitre_v151_ta0001_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0001"
  })
}

benchmark "mitre_v151_ta0001" {
  title         = "TA0001 Initial Access"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0001.md")
  children = [
    benchmark.mitre_v151_ta0001_t1078,
    benchmark.mitre_v151_ta0001_t1190,
    benchmark.mitre_v151_ta0001_t1566,
    benchmark.mitre_v151_ta0001_t1200,
    benchmark.mitre_v151_ta0001_t1199,
    benchmark.mitre_v151_ta0001_t1659,
    benchmark.mitre_v151_ta0001_t1189,
    benchmark.mitre_v151_ta0001_t1195,
  ]

  tags = merge(local.mitre_v151_ta0001_common_tags, {
    type = "Benchmark"
  })
}

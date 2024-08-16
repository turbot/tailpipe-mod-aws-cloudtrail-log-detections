locals {
  mitre_v151_ta0001_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0001"
  })
}

benchmark "mitre_v151_ta0001" {
  title         = "TA0001 Initial Access"
  //documentation = file("./cis_v130/docs/cis_v130_3.md")
  children = [
    benchmark.mitre_v151_ta0001_t1078,
    benchmark.mitre_v151_ta0001_t1190,
  ]

  tags = merge(local.mitre_v151_ta0001_common_tags, {
    type = "Benchmark"
  })
}

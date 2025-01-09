locals {
  mitre_v161_ta0006_common_tags = merge(local.mitre_v161_common_tags, {
    mitre_tactic_id = "TA0006"
  })
}

benchmark "mitre_v161_ta0006" {
  title         = "TA0006 Credential Access"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0006.md")
  children = [
    benchmark.mitre_v161_ta0006_t1552,
    benchmark.mitre_v161_ta0006_t1110
  ]

  tags = merge(local.mitre_v161_ta0006_common_tags, {
    type = "Benchmark"
  })
}

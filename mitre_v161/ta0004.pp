locals {
  mitre_v161_ta0004_common_tags = merge(local.mitre_v161_common_tags, {
    mitre_tactic_id = "TA0004"
  })
}

benchmark "mitre_v161_ta0004" {
  title         = "TA0004 Privilege Escalation"
  type          = "detection"
  documentation = file("./mitre_v161/docs/ta0004.md")
  children = [
    benchmark.mitre_v161_ta0004_t1078,
    benchmark.mitre_v161_ta0004_t1068,
    benchmark.mitre_v161_ta0004_t1098,
  ]

  tags = merge(local.mitre_v161_ta0004_common_tags, {
    type = "Benchmark"
  })
}

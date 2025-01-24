locals {
  mitre_attack_v161_ta0009_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_tactic_id = "TA0009"
  })
}

benchmark "mitre_attack_v161_ta0009" {
  title         = "TA0009 Collection"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0009.md")
  children = [
    benchmark.mitre_attack_v161_ta0009_t1560
  ]

  tags = merge(local.mitre_attack_v161_ta0009_common_tags, {
    type = "Benchmark"
  })
}

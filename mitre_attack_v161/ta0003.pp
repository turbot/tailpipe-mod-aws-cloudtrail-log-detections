locals {
  mitre_attack_v161_ta0003_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0003"
  })
}

benchmark "mitre_attack_v161_ta0003" {
  title         = "TA0003 Persistence"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1078,
    benchmark.mitre_attack_v161_ta0003_t1098,
    benchmark.mitre_attack_v161_ta0003_t1136,
    benchmark.mitre_attack_v161_ta0003_t1546,
  ]

  tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    type = "Benchmark"
  })
}

locals {
  mitre_attack_v161_ta0002_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0002"
  })
}

benchmark "mitre_attack_v161_ta0002" {
  title         = "TA0002 Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0002.md")
  children = [
    benchmark.mitre_attack_v161_ta0002_t1059,
    benchmark.mitre_attack_v161_ta0002_t1204,
    benchmark.mitre_attack_v161_ta0002_t1648,
  ]

  tags = merge(local.mitre_attack_v161_ta0002_common_tags, {
    type = "Benchmark"
  })
}

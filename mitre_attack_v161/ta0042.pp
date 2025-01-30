locals {
  mitre_attack_v161_ta0042_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0042"
  })
}

benchmark "mitre_attack_v161_ta0042" {
  title         = "TA0042 Execution"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0042.md")
  children = [
    benchmark.mitre_attack_v161_ta0042_t1583,
  ]

  tags = merge(local.mitre_attack_v161_ta0042_common_tags, {
    type = "Benchmark"
  })
}

locals {
  mitre_attack_v161_ta0008_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_tactic_id = "TA0008"
  })
}

benchmark "mitre_attack_v161_ta0008" {
  title         = "TA0008 Lateral Movement"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0008.md")
  children = [
    benchmark.mitre_attack_v161_ta0008_t1210,
    benchmark.mitre_attack_v161_ta0008_t1550,
  ]

  tags = merge(local.mitre_attack_v161_ta0008_common_tags, {
    type = "Benchmark"
  })
}

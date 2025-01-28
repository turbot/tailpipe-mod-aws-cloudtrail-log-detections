locals {
  mitre_attack_v161_ta0001_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0001"
  })
}

benchmark "mitre_attack_v161_ta0001" {
  title         = "TA0001 Initial Access"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0001.md")
  children = [
    benchmark.mitre_attack_v161_ta0001_t1078,
    benchmark.mitre_attack_v161_ta0001_t1190,
    benchmark.mitre_attack_v161_ta0001_t1199,
  ]

  tags = merge(local.mitre_attack_v161_ta0001_common_tags, {
    type = "Benchmark"
  })
}

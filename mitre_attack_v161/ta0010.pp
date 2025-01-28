locals {
  mitre_attack_v161_ta0010_common_tags = merge(local.mitre_attack_v161_common_tags, {
    mitre_attack_tactic_id = "TA0010"
  })
}

benchmark "mitre_attack_v161_ta0010" {
  title         = "TA0010 Exfiltration"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010.md")
  children = [
    benchmark.mitre_attack_v161_ta0010_t1048,
  ]

  tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    type = "Benchmark"
  })
}

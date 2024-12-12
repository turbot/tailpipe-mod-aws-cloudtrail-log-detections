locals {
  mitre_v151_ta0010_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0010"
  })
}

benchmark "mitre_v151_ta0010" {
  title         = "TA0010 Exfiltration"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010.md")
  children = [
    benchmark.mitre_v151_ta0010_t1029,
    benchmark.mitre_v151_ta0010_t1048,
    benchmark.mitre_v151_ta0010_t1530
  ]

  tags = merge(local.mitre_v151_ta0010_common_tags, {
    type = "Benchmark"
  })
}

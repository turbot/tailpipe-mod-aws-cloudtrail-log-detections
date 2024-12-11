locals {
  mitre_v151_ta0040_common_tags = merge(local.mitre_v151_common_tags, {
    mitre_tactic_id = "TA0040"
  })
}

benchmark "mitre_v151_ta0040" {
  title         = "TA0040 Impact"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040.md")
  children = [
    benchmark.mitre_v151_ta0040_t1484_001,
    benchmark.mitre_v151_ta0040_t1484_002,
    benchmark.mitre_v151_ta0040_t1485,
    benchmark.mitre_v151_ta0040_t1486,
    benchmark.mitre_v151_ta0040_t1487,
    benchmark.mitre_v151_ta0040_t1489,
    benchmark.mitre_v151_ta0040_t1490,
    benchmark.mitre_v151_ta0040_t1495,
    benchmark.mitre_v151_ta0040_t1496,
    benchmark.mitre_v151_ta0040_t1498,
    benchmark.mitre_v151_ta0040_t1499,
    benchmark.mitre_v151_ta0040_t1529,
    benchmark.mitre_v151_ta0040_t1561,
    benchmark.mitre_v151_ta0040_t1562_001,
  ]

  tags = merge(local.mitre_v151_ta0040_common_tags, {
    type = "Benchmark"
  })
}

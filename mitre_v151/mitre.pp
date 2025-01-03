locals {
  mitre_v151_common_tags = merge(local.aws_detections_common_tags, {
    mitre         = "true"
    mitre_version = "v15.1"
  })
}

// TODO: Should this be mitre_attack_v151?
benchmark "mitre_v151" {
  title         = "MITRE ATT&CK v15.1 for CloudTrail Logs"
  description   = "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
  type          = "detection"
  documentation = file("./mitre_v151/docs/mitre.md")
  children = [
    benchmark.mitre_v151_ta0001,
    benchmark.mitre_v151_ta0002,
    benchmark.mitre_v151_ta0003,
    benchmark.mitre_v151_ta0004,
    benchmark.mitre_v151_ta0005,
    benchmark.mitre_v151_ta0006,
    benchmark.mitre_v151_ta0008,
    benchmark.mitre_v151_ta0009,
    benchmark.mitre_v151_ta0010,
    benchmark.mitre_v151_ta0040,
  ]

  tags = merge(local.mitre_v151_common_tags, {
    type = "Benchmark"
  })
}

locals {
  mitre_attack_v161_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    mitre_attack_version = "v16.1"
  })
}

benchmark "mitre_attack_v161" {
  title         = "MITRE ATT&CK v16.1"
  description   = "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/mitre.md")
  children = [
    benchmark.mitre_attack_v161_ta0001,
    benchmark.mitre_attack_v161_ta0002,
    benchmark.mitre_attack_v161_ta0003,
    benchmark.mitre_attack_v161_ta0004,
    benchmark.mitre_attack_v161_ta0005,
    benchmark.mitre_attack_v161_ta0006,
    benchmark.mitre_attack_v161_ta0008,
    benchmark.mitre_attack_v161_ta0009,
    benchmark.mitre_attack_v161_ta0010,
    benchmark.mitre_attack_v161_ta0040,
    benchmark.mitre_attack_v161_ta0042,
  ]

  tags = merge(local.mitre_attack_v161_common_tags, {
    type = "Benchmark"
  })
}

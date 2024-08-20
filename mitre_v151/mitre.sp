locals {
  mitre_v151_common_tags = merge(local.aws_common_tags, {
    mitre         = "true"
    mitre_version = "v15.1"
  })
}

// TODO: Should this be mitre_attack_v151?
benchmark "mitre_v151" {
  title         = "MITRE ATT&CK v15.1"
  description   = "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations."
  documentation = file("./mitre_v151/docs/mitre.md")
  children = [
    benchmark.mitre_v151_ta0001,
    benchmark.mitre_v151_ta0005
  ]

  tags = merge(local.mitre_v151_common_tags, {
    type = "Benchmark"
  })
}

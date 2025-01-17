locals {
  mitre_attack_v161_ta0010_t1048_common_tags = merge(local.mitre_attack_v161_ta0010_common_tags, {
    mitre_technique_id = "T1048"
  })
}

benchmark "mitre_attack_v161_ta0010_t1048" {
  title         = "T1048 Exfiltration Over Alternative Protocol"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0010_t1048.md")
  children = [
    detection.cloudfront_distributions_failover_criteria_modified,

  ]

  tags = local.mitre_attack_v161_ta0010_t1048_common_tags
}


locals {
  mitre_attack_v161_ta0004_t1548_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_technique_id = "T1548"
  })
}


benchmark "mitre_attack_v161_ta0004_t1548" {
  title         = "T1548 Abuse Elevation Control Mechanism"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1548.md")
  children = [
    benchmark.mitre_attack_v161_ta0004_t1548_005,
  ]

  tags = local.mitre_attack_v161_ta0004_t1548_common_tags
}

benchmark "mitre_attack_v161_ta0004_t1548_005" {
  title         = "T1548.005 Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1548_005.md")
  children = [
    detection.detect_public_access_granted_to_lambda_functions,
    detection.s3_bucket_public_access_granted,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1548_common_tags, {
    mitre_subtechnique_id = "T1548.005"
  })
}
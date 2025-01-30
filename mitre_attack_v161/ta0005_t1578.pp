locals {
  mitre_attack_v161_ta0005_t1578_common_tags = merge(local.mitre_attack_v161_ta0005_common_tags, {
    mitre_attack_technique_id = "T1578"
  })
}

benchmark "mitre_attack_v161_ta0005_t1578" {
  title         = "T1578 Modify Cloud Compute Infrastructure"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1578.md")
  children = [
    benchmark.mitre_attack_v161_ta0005_t1578_005,
  ]

  tags = local.mitre_attack_v161_ta0005_t1578_common_tags
}

benchmark "mitre_attack_v161_ta0005_t1578_005" {
  title         = "T1578.005 Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0005_t1578_001.md")
  children = [
    detection.cloudtrail_trail_global_service_logging_disabled,
    detection.ebs_encryption_by_default_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0005_t1578_common_tags, {
    mitre_attack_technique_id = "T1578.005"
  })
}

locals {
  mitre_attack_v161_ta0003_t1556_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_attack_technique_id = "T1556"
  })
}

benchmark "mitre_attack_v161_ta0003_t1556" {
  title         = "T1556 Modify Authentication Process"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1556_006
  ]

  tags = local.mitre_attack_v161_ta0003_t1556_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1556_006" {
  title         = "T1556.006 Modify Authentication Process: Multi-Factor Authentication"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556_006.md")
  children = [
    detection.iam_user_mfa_device_deactivated,
  ]

  tags = merge(local.mitre_attack_v161_ta0003_t1556_common_tags, {
    mitre_attack_technique_id = "T1556.006"
  })
}

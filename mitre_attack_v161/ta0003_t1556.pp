locals {
  mitre_attack_v161_ta0003_t1556_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1556"
  })
}

benchmark "mitre_attack_v161_ta0003_t1556" {
  title         = "T1556 Modify Authentication Process"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1556_006,
    benchmark.mitre_attack_v161_ta0003_t1556_007,
    benchmark.mitre_attack_v161_ta0003_t1556_009,
  ]

  tags = local.mitre_attack_v161_ta0003_t1556_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1556_006" {
  title         = "T1556.001 Modify Authentication Process: Multi-Factor Authentication"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556_006.md")
  children = [
    detection.detect_iam_users_with_mfa_disabled,
  ]

  tags = merge(local.mitre_attack_v161_ta0003_t1556_common_tags, {
    mitre_technique_id = "T1556.001"
  })
}

benchmark "mitre_attack_v161_ta0003_t1556_007" {
  title         = "T1556.004 Modify Authentication Process: Hybrid Identity"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556_007.md")
  children = [
    #TODO: Add detections
  ]

  tags = merge(local.mitre_attack_v161_ta0003_t1556_common_tags, {
    mitre_technique_id = "T1556.004"
  })
}

benchmark "mitre_attack_v161_ta0003_t1556_009" {
  title         = "T1556.004 Modify Authentication Process: Conditional Access Policies"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1556_009.md")
  children = [
    detection.detect_public_access_granted_to_iam_groups,
    detection.detect_public_access_granted_to_iam_roles,
    detection.detect_public_access_granted_to_iam_users,
  ]

  tags = merge(local.mitre_attack_v161_ta0003_t1556_common_tags, {
    mitre_technique_id = "T1556.004"
  })
}
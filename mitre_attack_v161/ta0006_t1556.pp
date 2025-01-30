locals {
  mitre_attack_v161_ta0006_t1556_common_tags = merge(local.mitre_attack_v161_ta0006_common_tags, {
    mitre_attack_technique_id = "T1556"
  })
}

benchmark "mitre_attack_v161_ta0006_t1556" {
  title         = "T1556 Modify Authentication Process"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1556.md")
  children = [
    benchmark.mitre_attack_v161_ta0006_t1556_006,
    benchmark.mitre_attack_v161_ta0006_t1556_003,
  ]

  tags = local.mitre_attack_v161_ta0006_t1556_common_tags
}

benchmark "mitre_attack_v161_ta0006_t1556_003" {
  title         = "T1556.003 Modify Authentication Process: Pluggable Authentication Modules"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1556_003.md")
  children = [
    detection.iam_user_login_profile_updated,
  ]

  tags = merge(local.mitre_attack_v161_ta0006_t1556_common_tags, {
    mitre_attack_technique_id = "T1556.003"
  })
}


benchmark "mitre_attack_v161_ta0006_t1556_006" {
  title         = "T1556.006 Unsecured Credentials: Multi-Factor Authentication"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1556_006.md")
  children = [
    detection.iam_user_mfa_device_deactivated,
  ]

  tags = merge(local.mitre_attack_v161_ta0006_t1556_common_tags, {
    mitre_attack_technique_id = "T1556.006"
  })
}


locals {
  mitre_attack_v161_ta0004_t1078_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_attack_technique_id = "T1078"
  })
}

benchmark "mitre_attack_v161_ta0004_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078.md")
  children = [
    benchmark.mitre_attack_v161_ta0004_t1078_001,
    benchmark.mitre_attack_v161_ta0004_t1078_004,
    benchmark.mitre_attack_v161_ta0004_t1078_003,
  ]

  tags = local.mitre_attack_v161_ta0004_t1078_common_tags
}

benchmark "mitre_attack_v161_ta0004_t1078_001" {
  title         = "T1078.001 Valid Accounts: Default Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078_001.md")
  children = [
    detection.iam_root_user_console_login,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1078_common_tags, {
    mitre_attack_technique_id = "T1078.001"
  })
}

benchmark "mitre_attack_v161_ta0004_t1078_003" {
  title         = "T1078.003 Valid Accounts: Local Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078_003.md")
  children = [
    detection.iam_root_user_console_login,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1078_common_tags, {
    mitre_attack_technique_id = "T1078.003"
  })
}

benchmark "mitre_attack_v161_ta0004_t1078_004" {
  title         = "T1078.004 Valid Accounts: Cloud Accounts"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1078_004.md")
  children = [
    detection.iam_access_key_created,
    detection.iam_access_key_deleted,
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1078_common_tags, {
    mitre_attack_technique_id = "T1078.004"
  })
}
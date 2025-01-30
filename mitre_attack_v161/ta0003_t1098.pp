locals {
  mitre_attack_v161_ta0003_t1098_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_attack_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098.md")
  children = [
    benchmark.mitre_attack_v161_ta0003_t1098_001,
    benchmark.mitre_attack_v161_ta0003_t1098_003,
    benchmark.mitre_attack_v161_ta0003_t1098_004,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_001" {
  title         = "T1098.001 Account Manipulation: Additional Cloud Credentials"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_001.md")
  children = [
    detection.iam_user_created,
    detection.iam_user_login_profile_updated,
    detection.rds_db_instance_master_password_updated,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_003" {
  title         = "T1098.003 Account Manipulation: Additional Cloud Roles"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_003.md")
  children = [
    detection.iam_role_inline_policy_updated,
    detection.iam_user_login_profile_created,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_004" {
  title         = "T1098.004 Account Manipulation: SSH Authorized Keys"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_004.md")
  children = [
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all,
    detection.vpc_security_group_ingress_egress_rule_updated,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
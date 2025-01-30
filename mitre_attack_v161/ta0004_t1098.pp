locals {
  mitre_attack_v161_ta0004_t1098_common_tags = merge(local.mitre_attack_v161_ta0004_common_tags, {
    mitre_attack_technique_id = "T1098"
  })
}

benchmark "mitre_attack_v161_ta0004_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1098.md")
  children = [
    benchmark.mitre_attack_v161_ta0004_t1098_001,
    benchmark.mitre_attack_v161_ta0004_t1098_003,
    benchmark.mitre_attack_v161_ta0004_t1098_004,
  ]

  tags = local.mitre_attack_v161_ta0004_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0004_t1098_001" {
  title         = "T1098.001 Account Manipulation: Additional Cloud Credentials"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1098_001.md")
  children = [
    detection.iam_user_created,
    detection.iam_user_login_profile_created,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1098_common_tags, {
    mitre_attack_technique_id = "T1098.001"
  })
}

benchmark "mitre_attack_v161_ta0004_t1098_003" {
  title         = "T1098.003 Account Manipulation: Additional Cloud Roles"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1098_003.md")
  children = [
    detection.codebuild_project_service_role_updated,
    detection.iam_group_administrator_policy_attached,
    detection.iam_group_inline_policy_updated,
    detection.iam_role_inline_policy_updated,
    detection.iam_role_managed_policy_attached,
    detection.iam_user_administrator_policy_attached,
    detection.iam_user_inline_policy_updated,
    detection.iam_user_managed_policy_attached,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1098_common_tags, {
    mitre_attack_technique_id = "T1098.003"
  })
}

benchmark "mitre_attack_v161_ta0004_t1098_004" {
  title         = "T1098.004 Account Manipulation: SSH Authorized Keys"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0004_t1098_004.md")
  children = [
    detection.vpc_security_group_ingress_egress_rule_authorized_to_allow_all,
    detection.vpc_security_group_ingress_egress_rule_updated,
  ]

  tags = merge(local.mitre_attack_v161_ta0004_t1098_common_tags, {
    mitre_attack_technique_id = "T1098.004"
  })
}
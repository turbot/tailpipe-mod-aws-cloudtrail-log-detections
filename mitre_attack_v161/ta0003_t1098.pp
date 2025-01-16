locals {
  mitre_attack_v161_ta0003_t1098_common_tags = merge(local.mitre_attack_v161_ta0003_common_tags, {
    mitre_technique_id = "T1098"
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
    detection.detect_iam_user_creations,
    detection.detect_iam_users_with_console_access_enabled,
    detection.detect_rds_db_instance_master_password_updates,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_003" {
  title         = "T1098.003 Account Manipulation: Additional Cloud Roles"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_003.md")
  children = [
    detection.detect_public_access_granted_to_iam_users,
    detection.detect_admin_access_granted_to_iam_roles,
    detection.detect_admin_access_granted_to_iam_users,
    detection.detect_iam_role_inline_policy_creations,
    detection.detect_admin_access_granted_to_iam_groups,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}

benchmark "mitre_attack_v161_ta0003_t1098_004" {
  title         = "T1098.004 Account Manipulation: SSH Authorized Keys"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0003_t1098_004.md")
  children = [
    detection.detect_vpc_security_group_ipv4_allow_all,
    detection.detect_vpc_security_group_ipv6_allow_all,
    detection.detect_vpc_security_group_ingress_egress_updates,
  ]

  tags = local.mitre_attack_v161_ta0003_t1098_common_tags
}
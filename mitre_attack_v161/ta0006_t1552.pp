locals {
  mitre_attack_v161_ta0006_t1552_common_tags = merge(local.mitre_attack_v161_ta0006_common_tags, {
    mitre_attack_technique_id = "T1552"
  })
}

benchmark "mitre_attack_v161_ta0006_t1552" {
  title         = "T1552 Unsecured Credentials"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1552.md")
  children = [
    benchmark.mitre_attack_v161_ta0006_t1552_004
  ]

  tags = local.mitre_attack_v161_ta0006_t1552_common_tags
}

benchmark "mitre_attack_v161_ta0006_t1552_004" {
  title         = "T1552.004 Unsecured Credentials: Private Keys"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0006_t1552_004.md")
  children = [
    detection.codebuild_project_environment_variable_updated,
    detection.iam_access_key_created,
    detection.iam_access_key_deleted,
    detection.iam_user_login_profile_created,
  ]

  tags = merge(local.mitre_attack_v161_ta0006_t1552_common_tags, {
    mitre_attack_technique_id = "T1552.004"
  })
}


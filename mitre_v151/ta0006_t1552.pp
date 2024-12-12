locals {
  mitre_v151_ta0006_t1552_common_tags = merge(local.mitre_v151_ta0006_common_tags, {
    mitre_technique_id = "T1552"
  })
}

benchmark "mitre_v151_ta0006_t1552" {
  title         = "T1552 Unsecured Credentials"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1552.md")
  children = [
    benchmark.mitre_v151_ta0006_t1552_004,
    benchmark.mitre_v151_ta0006_t1552_007
  ]

  tags = local.mitre_v151_ta0006_t1552_common_tags
}

benchmark "mitre_v151_ta0006_t1552_004" {
  title         = "t1552.004 Private Keys"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1552_004.md")
  children = [
    detection.cloudtrail_logs_detect_iam_access_key_creation,
    detection.cloudtrail_logs_detect_iam_access_key_deletion

  ]

  tags = merge(local.mitre_v151_ta0006_t1552_common_tags, {
    mitre_technique_id = "t1552.004"
  })
}

benchmark "mitre_v151_ta0006_t1552_007" {
  title         = "t1552.007 Container API"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1552_007.md")
  children = [
    detection.cloudtrail_logs_detect_secrets_manager_secret_access,
    detection.cloudtrail_logs_detect_ssm_parameter_store_access

  ]

  tags = merge(local.mitre_v151_ta0006_t1552_common_tags, {
    mitre_technique_id = "t1552.007"
  })
}

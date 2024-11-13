locals {
  mitre_v151_ta0003_t1098_common_tags = merge(local.mitre_v151_ta0003_common_tags, {
    mitre_technique_id = "T1098"
  })
}

detection_benchmark "mitre_v151_ta0003_t1098" {
  title         = "T1098 Account Manipulation"
  type          = "benchmark"
  documentation = file("./mitre_v151/docs/ta0003_t1098.md")
  children = [
    detection.cloudtrail_logs_detect_iam_user_login_profile_updates
  ]

  tags = local.mitre_v151_ta0003_t1098_common_tags
}

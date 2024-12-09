locals {
  mitre_v151_ta0006_t1110_common_tags = merge(local.mitre_v151_ta0006_common_tags, {
    mitre_technique_id = "T1110"
  })
}

benchmark "mitre_v151_ta0006_t1110" {
  title         = "T1110 Brute Force"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0006_t1110.md")
  children = [
    detection.cloudtrail_logs_detect_iam_user_password_change
  ]

  tags = local.mitre_v151_ta0006_t1110_common_tags
}


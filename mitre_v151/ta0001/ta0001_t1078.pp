locals {
  mitre_v151_ta0001_t1078_common_tags = merge(local.mitre_v151_ta0001_common_tags, {
    mitre_technique_id = "T1078"
  })
}

detection_benchmark "mitre_v151_ta0001_t1078" {
  title         = "T1078 Valid Accounts"
  type          = "benchmark"
  documentation = file("./mitre_v151/docs/ta0001_t1078.md")
  children = [
    detection.cloudtrail_log_iam_root_console_logins
  ]

  tags = local.mitre_v151_ta0001_t1078_common_tags
}

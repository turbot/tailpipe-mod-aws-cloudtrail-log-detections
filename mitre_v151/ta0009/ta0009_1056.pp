locals {
  mitre_v151_ta0009_t1056_common_tags = merge(local.mitre_v151_ta0009_common_tags, {
    mitre_technique_id = "T1056"
  })
}

benchmark "mitre_v151_ta0009_t1056" {
  title         = "T1056 Input Capture"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0009_t1056.md")
  children = [
    detection.cloudtrail_logs_detect_ssm_unauthorized_input_captures
  ]

  tags = local.mitre_v151_ta0009_t1056_common_tags
}


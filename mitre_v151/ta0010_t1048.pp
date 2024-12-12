locals {
  mitre_v151_ta0010_t1048_common_tags = merge(local.mitre_v151_ta0010_common_tags, {
    mitre_technique_id = "T1048"
  })
}

benchmark "mitre_v151_ta0010_t1048" {
  title         = "T1048 Exfiltration Over Alternative Protocol"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0010_t1048.md")
  children = [
    detection.cloudtrail_logs_detect_cloudfront_distribution_updates
  ]

  tags = local.mitre_v151_ta0010_t1048_common_tags
}


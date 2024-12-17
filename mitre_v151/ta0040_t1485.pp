locals {
  mitre_v151_ta0040_t1485_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1485"
  })
}

benchmark "mitre_v151_ta0040_t1485" {
  title         = "T1485 Data Destruction"
  type          = "detection"
  documentation = file("./mitre_v151/docs/ta0040_t1485.md")
  children = [
    detection.cloudtrail_logs_detect_s3_bucket_deleted,
    detection.cloudtrail_logs_detect_s3_object_deleted,
    detection.cloudtrail_logs_detect_eventbridge_rule_deletions,
    detection.cloudtrail_logs_detect_guardduty_detector_deletions,
  ]

  tags = local.mitre_v151_ta0040_t1485_common_tags
}

locals {
  cloudtrail_log_detection_guardduty_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/GuardDuty"
  })

  cloudtrail_logs_detect_guardduty_detector_deletions_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.detectorId")
}

benchmark "cloudtrail_logs_guardduty_detections" {
  title       = "GuardDuty"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for GuardDuty events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_guardduty_detector_deletions
  ]

  tags = merge(local.cloudtrail_log_detection_guardduty_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_guardduty_detector_deletions" {
  title       = "Detect GuardDuty Detectors Deletion Updates"
  description = "Detect GuardDuty detectors deletion updates to check for unauthorized changes."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_guardduty_detector_deletions

  tags = merge(local.cloudtrail_log_detection_guardduty_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001, TA0040:T1485"
  })
}

query "cloudtrail_logs_detect_guardduty_detector_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_guardduty_detector_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'guardduty.amazonaws.com'
      and event_name = 'DeleteDetector'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

locals {
  cloudtrail_logs_detect_guardduty_detector_deletion_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.detectorId")
}

benchmark "cloudtrail_logs_guardduty_detections" {
  title       = "CloudTrail Log GuardDuty Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's GuardDuty logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_guardduty_detector_deletion_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/GuardDuty"
  })
}

detection "cloudtrail_logs_detect_guardduty_detector_deletion_updates" {
  title       = "Detect GuardDuty Detectors Deletion Updates"
  description = "Detect GuardDuty detectors deletion updates to check for unauthorized changes."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_guardduty_detector_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "cloudtrail_logs_detect_guardduty_detector_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_guardduty_detector_deletion_updates_sql_columns}
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

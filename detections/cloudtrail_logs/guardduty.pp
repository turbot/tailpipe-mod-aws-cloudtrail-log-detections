benchmark "cloudtrail_logs_guardduty_detections" {
  title       = "CloudTrail Log GuardDuty Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's GuardDuty logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_guardduty_detector_deletion_updates,
  ]
}

detection "cloudtrail_logs_detect_guardduty_detector_deletion_updates" {
  title       = "Detect GuardDuty Detector Deletion Updates"
  description = "Detect GuardDuty detector deletion updates to check for unauthorized changes."
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
      and error_code is null
    order by
      event_time desc;
  EOQ
}

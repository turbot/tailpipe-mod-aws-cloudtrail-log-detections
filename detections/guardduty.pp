locals {
  guardduty_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/GuardDuty"
  })

  detect_guardduty_detector_deletions_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.detectorId')")
}

benchmark "guardduty_detections" {
  title       = "GuardDuty Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for GuardDuty events."
  type        = "detection"
  children    = [
    detection.detect_guardduty_detector_deletions
  ]

  tags = merge(local.guardduty_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_guardduty_detector_deletions" {
  title           = "Detect GuardDuty Detector Deletions"
  description     = "Detect when GuardDuty detectors are deleted. Deleting GuardDuty detectors disables threat detection capabilities, which can allow malicious activities to go undetected and impair your ability to respond to security incidents."
  documentation   = file("./detections/docs/detect_guardduty_detector_deletions.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_guardduty_detector_deletions

  tags = merge(local.guardduty_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001, TA0040:T1485"
  })
}

query "detect_guardduty_detector_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_guardduty_detector_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'guardduty.amazonaws.com'
      and event_name = 'DeleteDetector'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

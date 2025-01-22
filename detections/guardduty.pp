locals {
  guardduty_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/GuardDuty"
  })

}

benchmark "guardduty_detections" {
  title       = "GuardDuty Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for GuardDuty events."
  type        = "detection"
  children    = [
    detection.guardduty_detector_deleted
  ]

  tags = merge(local.guardduty_common_tags, {
    type    = "Benchmark"
  })
}

detection "guardduty_detector_deleted" {
  title           = "GuardDuty Detector Deleted"
  description     = "Detect when a GuardDuty detector was deleted to check for potential risks of disabled threat detection capabilities, which could allow malicious activities to go undetected and impair incident response."
  documentation   = file("./detections/docs/guardduty_detector_deleted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.guardduty_detector_deleted

  tags = merge(local.guardduty_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001,TA0040:T1485"
  })
}

query "guardduty_detector_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_detector_id}
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

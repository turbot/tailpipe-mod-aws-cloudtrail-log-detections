locals {
  cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns                  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_cloudtrail_detections" {
  title       = "CloudTrail Log CloudTrail Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CloudTrail logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudtrail_trail_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/CloudTrail"
  })
}

detection "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  title       = "Detect CloudTrail Trail Updates"
  description = "Detect CloudTrail trail changes to check if logging was stopped."
  severity    = "medium"
  documentation        = file("./detections/docs/cloudtrail_logs_detect_cloudtrail_trail_updates.md")
  query       = query.cloudtrail_logs_detect_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('DeleteTrail', 'StopLogging', 'UpdateTrail')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

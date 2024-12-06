benchmark "cloudtrail_logs_cloudwatch_detections" {
  title       = "CloudTrail Log CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CloudWatch logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates,
  ]
}

detection "cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates" {
  title       = "Detect CloudWatch Log Group Deletion Updates"
  description = "Detect CloudWatch log group deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates" {
  title       = "Detect CloudWatch Log Stream Deletion Updates"
  description = "Detect CloudWatch log stream deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates" {
  title       = "Detect CloudWatch Alarm Deletion Updates"
  description = "Detect CloudWatch alarm deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'DeleteLogGroup'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'DeleteLogStream'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'DeleteAlarms'
      and error_code is null
    order by
      event_time desc;
  EOQ
}
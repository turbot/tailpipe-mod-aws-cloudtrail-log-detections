locals {
  cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.logGroupName")
  cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.logStreamName")
  cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.alarmNames")
}

benchmark "cloudtrail_logs_cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CloudWatch logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/CloudWatch"
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates" {
  title       = "Detect CloudWatch Log Groups Deletion Updates"
  description = "Detect CloudWatch log groups deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_group_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates" {
  title       = "Detect CloudWatch Log Streams Deletion Updates"
  description = "Detect CloudWatch log streams deletion updates to check for unauthorized changes."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudwatch_log_stream_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_deletion_updates" {
  title       = "Detect CloudWatch Alarms Deletion Updates"
  description = "Detect CloudWatch alarms deletion updates to check for unauthorized changes."
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
locals {
  cloudtrail_log_detection_cloudwatch_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/CloudWatch"
  })

  cloudtrail_logs_detect_cloudwatch_log_group_deletions_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  cloudtrail_logs_detect_cloudwatch_log_stream_deletions_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logStreamName')")
  cloudtrail_logs_detect_cloudwatch_alarm_deletions_sql_columns      = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.alarmNames')")
}

benchmark "cloudtrail_logs_cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudWatch events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudwatch_log_group_deletions,
    detection.cloudtrail_logs_detect_cloudwatch_log_stream_deletions,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_group_deletions" {
  title           = "Detect CloudWatch Log Group Deletions"
  description     = "Detect CloudWatch log groups deletion updates to check for unauthorized changes."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_log_group_deletions

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_stream_deletions" {
  title           = "Detect CloudWatch Log Stream Deletions"
  description     = "Detect CloudWatch log streams deletion updates to check for unauthorized changes."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_log_stream_deletions

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_deletions" {
  title           = "Detect CloudWatch Alarm Deletions"
  description     = "Detect CloudWatch alarms deletion updates to check for unauthorized changes."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_alarm_deletions

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudwatch_log_group_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_group_deletions_sql_columns}
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

query "cloudtrail_logs_detect_cloudwatch_log_stream_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_stream_deletions_sql_columns}
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

query "cloudtrail_logs_detect_cloudwatch_alarm_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_deletions_sql_columns}
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

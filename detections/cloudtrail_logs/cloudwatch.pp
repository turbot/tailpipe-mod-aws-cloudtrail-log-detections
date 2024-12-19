locals {
  cloudtrail_log_detection_cloudwatch_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/CloudWatch"
  })

  cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.alarmName')")
  cloudtrail_logs_detect_cloudwatch_log_retention_period_changes_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  cloudtrail_logs_detect_cloudwatch_subscription_filter_changes_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  cloudtrail_logs_detect_cloudwatch_alarm_action_changes_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.alarmName')")
  cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.alarmName')")
  cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
}

benchmark "cloudtrail_logs_cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudWatch events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes,
    detection.cloudtrail_logs_detect_cloudwatch_log_retention_period_changes,
    detection.cloudtrail_logs_detect_cloudwatch_subscription_filter_changes,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_action_changes,
    detection.cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role,
    detection.cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role,
    detection.cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role,
  ]

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption" {
  title           = "Detect CloudWatch Log Groups Created Without Encryption"
  description     = "Detect events where CloudWatch log groups are created without KMS encryption enabled, potentially exposing sensitive log data to unauthorized access."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_groups_created_without_encryption_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'CreateLogGroup'
      and json_extract_string(request_parameters, '$.kmsKeyId') is null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes" {
  title           = "Detect CloudWatch Alarm Threshold Changes"
  description     = "Detect events where thresholds for CloudWatch alarms are modified, potentially impacting the accuracy of monitoring alerts."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1562.003"
  })
}

query "cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_threshold_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'PutMetricAlarm'
      and json_extract_string(request_parameters, '$.threshold') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_log_retention_period_changes" {
  title           = "Detect CloudWatch Log Retention Period Changes"
  description     = "Detect events where retention periods for CloudWatch logs are modified, potentially reducing the duration of stored log data."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_log_retention_period_changes

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudwatch_log_retention_period_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_retention_period_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutRetentionPolicy'
      and json_extract_string(request_parameters, '$.retentionInDays') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_subscription_filter_changes" {
  title           = "Detect CloudWatch Subscription Filter Changes"
  description     = "Detect events where subscription filters for CloudWatch logs are modified, potentially redirecting logs to unauthorized destinations."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_subscription_filter_changes

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudtrail_logs_detect_cloudwatch_subscription_filter_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_subscription_filter_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutSubscriptionFilter'
      and json_extract_string(request_parameters, '$.destinationArn') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_action_changes" {
  title           = "Detect CloudWatch Alarm Action Changes"
  description     = "Detect events where actions for CloudWatch alarms are modified, potentially affecting the response to triggered alarms."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_alarm_action_changes

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1562.003"
  })
}

query "cloudtrail_logs_detect_cloudwatch_alarm_action_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_action_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'PutMetricAlarm'
      and json_extract_string(request_parameters, '$.alarmActions') is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role" {
  title           = "Detect CloudWatch Log Group Shared via Cross-Account Role"
  description     = "Detect events where CloudWatch log groups are shared using the `CloudWatch-CrossAccountSharingRole`, which could indicate intentional or unintentional cross-account sharing."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_log_group_shared_via_cross_account_role_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutResourcePolicy'
      and json_extract_string(request_parameters, '$.policyDocument') like '%"AWS":"arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role" {
  title           = "Detect CloudWatch Alarm Actions Configured via Cross-Account Role"
  description     = "Detect events where CloudWatch alarm actions are configured to use the `CloudWatch-CrossAccountSharingRole`, potentially allowing cross-account activity."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_alarm_actions_via_cross_account_role_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'PutMetricAlarm'
      and json_extract_string(request_parameters, '$.alarmActions') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role" {
  title           = "Detect CloudWatch Subscription Filters Redirected via Cross-Account Role"
  description     = "Detect events where CloudWatch subscription filters redirect logs using the `CloudWatch-CrossAccountSharingRole`, potentially leading to cross-account data access."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role

  tags = merge(local.cloudtrail_log_detection_cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudwatch_subscription_filters_via_cross_account_role_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutSubscriptionFilter'
      and json_extract_string(request_parameters, '$.destinationArn') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

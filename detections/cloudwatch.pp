locals {
  cloudwatch_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudWatch"
  })

  detect_cloudwatch_log_groups_created_without_encryption_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  detect_cloudwatch_logs_retention_period_updates_sql_columns                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  detect_cloudwatch_subscriptions_filter_updates_sql_columns                 = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  detect_cloudwatch_log_groups_shared_via_cross_account_roles_sql_columns    = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
  detect_cloudwatch_alarms_actions_via_cross_account_roles_sql_columns       = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.alarmName')")
  detect_cloudwatch_subscription_filters_via_cross_account_roles_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.logGroupName')")
}

benchmark "cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudWatch events."
  type        = "detection"
  children = [
    detection.detect_cloudwatch_log_groups_created_without_encryption,
    detection.detect_cloudwatch_logs_retention_period_updates,
    detection.detect_cloudwatch_subscriptions_filter_updates,
    detection.detect_cloudwatch_log_groups_shared_via_cross_account_roles,
    detection.detect_cloudwatch_alarms_actions_via_cross_account_roles,
    detection.detect_cloudwatch_subscription_filters_via_cross_account_roles,
  ]

  tags = merge(local.cloudwatch_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_cloudwatch_log_groups_created_without_encryption" {
  title           = "Detect CloudWatch Log Groups Created Without Encryption"
  description     = "Detect events where CloudWatch log groups are created without KMS encryption enabled, potentially exposing sensitive log data to unauthorized access."
  documentation   = file("./detections/docs/detect_cloudwatch_log_groups_created_without_encryption.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_log_groups_created_without_encryption

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "detect_cloudwatch_log_groups_created_without_encryption" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_log_groups_created_without_encryption_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'CreateLogGroup'
      and json_extract_string(request_parameters, '$.kmsKeyId') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

# TODO: Update detection name and description to match title and query
detection "detect_cloudwatch_logs_retention_period_updates" {
  title           = "Detect CloudWatch Log Retention Periods Shorter Than 30 Days"
  description     = "Detect events where retention periods for CloudWatch logs are modified, potentially reducing the duration of stored log data."
  documentation   = file("./detections/docs/detect_cloudwatch_logs_retention_period_updates.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_logs_retention_period_updates

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1562.001"
  })
}

query "detect_cloudwatch_logs_retention_period_updates" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_logs_retention_period_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutRetentionPolicy'
      and json_extract_string(request_parameters, '$.retentionInDays')::int < 30
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudwatch_subscriptions_filter_updates" {
  title           = "Detect CloudWatch Subscription Filter Updates"
  description     = "Detect events where subscription filters for CloudWatch logs are modified, potentially redirecting logs to unauthorized destinations."
  documentation   = file("./detections/docs/detect_cloudwatch_subscriptions_filter_updates.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_subscriptions_filter_updates

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "detect_cloudwatch_subscriptions_filter_updates" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_subscriptions_filter_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutSubscriptionFilter'
      and json_extract_string(request_parameters, '$.destinationArn') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudwatch_log_groups_shared_via_cross_account_roles" {
  title           = "Detect CloudWatch Log Group Shared via Cross-Account Roles"
  description     = "Detect events where CloudWatch log groups are shared using the `CloudWatch-CrossAccountSharingRole`, which could indicate intentional or unintentional cross-account sharing."
  documentation   = file("./detections/docs/detect_cloudwatch_log_groups_shared_via_cross_account_roles.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_log_groups_shared_via_cross_account_roles

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "detect_cloudwatch_log_groups_shared_via_cross_account_roles" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_log_groups_shared_via_cross_account_roles_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutResourcePolicy'
      and json_extract_string(request_parameters, '$.policyDocument') like '%"AWS":"arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudwatch_alarms_actions_via_cross_account_roles" {
  title           = "Detect CloudWatch Alarm Actions Configured via Cross-Account Roles"
  description     = "Detect events where CloudWatch alarm actions are configured to use the `CloudWatch-CrossAccountSharingRole`, potentially allowing cross-account activity."
  documentation   = file("./detections/docs/detect_cloudwatch_alarms_actions_via_cross_account_roles.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_alarms_actions_via_cross_account_roles

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "detect_cloudwatch_alarms_actions_via_cross_account_roles" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_alarms_actions_via_cross_account_roles_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'PutMetricAlarm'
      and json_extract_string(request_parameters, '$.alarmActions') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudwatch_subscription_filters_via_cross_account_roles" {
  title           = "Detect CloudWatch Subscription Filters Redirected via Cross-Account Role"
  description     = "Detect events where CloudWatch subscription filters redirect logs using the `CloudWatch-CrossAccountSharingRole`, potentially leading to cross-account data access."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudwatch_subscription_filters_via_cross_account_roles

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "detect_cloudwatch_subscription_filters_via_cross_account_roles" {
  sql = <<-EOQ
    select
      ${local.detect_cloudwatch_subscription_filters_via_cross_account_roles_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutSubscriptionFilter'
      and json_extract_string(request_parameters, '$.destinationArn') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

locals {
  cloudwatch_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudWatch"
  })
}

benchmark "cloudwatch_detections" {
  title       = "CloudWatch Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudWatch events."
  type        = "detection"
  children = [
    detection.cloudwatch_log_group_created_with_encryption_disabled,
    detection.cloudwatch_log_group_shared_via_cross_account_role,
    detection.cloudwatch_alarm_action_configured_via_cross_account_role,
    detection.cloudwatch_subscription_filter_redirected_via_cross_account_role,
  ]

  tags = merge(local.cloudwatch_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudwatch_log_group_created_with_encryption_disabled" {
  title           = "CloudWatch Log Group Created with Encryption Disabled"
  description     = "Detect when a CloudWatch log group was created with encryption disabled to check for potential risks of data exposure and non-compliance with security policies."
  documentation   = file("./detections/docs/cloudwatch_log_group_created_with_encryption_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudwatch_log_group_created_with_encryption_disabled

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudwatch_log_group_created_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_log_group_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'CreateLogGroup'
      and (request_parameters ->> 'kmsKeyId') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudwatch_log_group_shared_via_cross_account_role" {
  title           = "CloudWatch Log Group Shared via Cross-Account Role"
  description     = "Detect when a CloudWatch log group was shared using the `CloudWatch-CrossAccountSharingRole`, which could have exposed sensitive log data to unauthorized accounts and introduced significant security risks."
  documentation   = file("./detections/docs/cloudwatch_log_group_shared_via_cross_account_role.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudwatch_log_group_shared_via_cross_account_role

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "TA0003:T1537"
  })
}

query "cloudwatch_log_group_shared_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_log_group_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutResourcePolicy'
      and (request_parameters ->> 'policyDocument') like '%"AWS":"arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudwatch_alarm_action_configured_via_cross_account_role" {
  title           = "CloudWatch Alarm Action Configured via Cross-Account Role"
  description     = "Detect when a CloudWatch alarm action was configured using the `CloudWatch-CrossAccountSharingRole`, to check for potential cross-account activity that could introduce security risks or unauthorized access."
  documentation   = file("./detections/docs/cloudwatch_alarm_action_configured_via_cross_account_role.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudwatch_alarm_action_configured_via_cross_account_role

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudwatch_alarm_action_configured_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_alarm_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'monitoring.amazonaws.com'
      and event_name = 'PutMetricAlarm'
      and (request_parameters ->> 'alarmActions') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudwatch_subscription_filter_redirected_via_cross_account_role" {
  title           = "CloudWatch Subscription Filter Redirected via Cross-Account Role"
  description     = "Detect when a CloudWatch subscription filter was redirected via the `CloudWatch-CrossAccountSharingRole`, potentially allowing unauthorized cross-account data access and exposing sensitive logs to external parties."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudwatch_subscription_filter_redirected_via_cross_account_role

  tags = merge(local.cloudwatch_common_tags, {
    mitre_attack_ids = "T1537"
  })
}

query "cloudwatch_subscription_filter_redirected_via_cross_account_role" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_log_group_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'logs.amazonaws.com'
      and event_name = 'PutSubscriptionFilter'
      and (request_parameters ->> 'destinationArn') like '%arn:aws:iam::%:role/CloudWatch-CrossAccountSharingRole%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

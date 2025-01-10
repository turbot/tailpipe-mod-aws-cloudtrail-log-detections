locals {
  cloudtrail_log_detection_sns_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/SNS"
  })

  cloudtrail_logs_detect_public_access_granted_to_sns_topics_sql_columns               = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.topicArn')")
  cloudtrail_logs_detect_sns_topics_subscription_deletions_sql_columns                 = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.subscriptionArn')")
  cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.subscriptionArn')")
  cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates_sql_columns        = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.topicArn')")
}

benchmark "cloudtrail_logs_sns_detections" {
  title       = "SNS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SNS events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_public_access_granted_to_sns_topics,
    detection.cloudtrail_logs_detect_sns_topics_subscription_deletions,
    detection.cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates,
    detection.cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates.
  ]

  tags = merge(local.cloudtrail_log_detection_sns_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_sns_topics" {
  title           = "Detect Public Access Granted to SNS Topics"
  description     = "Detect when a public policy is added to an SNS topic to check for potential unauthorized access, which could expose sensitive notifications to external entities."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest

  tags = merge(local.cloudtrail_log_detection_sns_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

// Need to refactor the query to iterate the policy statements from the logs and check any of the statement have public access.
query "cloudtrail_logs_detect_public_access_granted_to_sns_topics" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_sns_topics_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and json_extract_string(request_parameters, '$.attributeName') = 'Policy'
      and json_extract_string(request_parameters, '$.attributeValue') like '%"Effect": "Allow"%'
      and json_extract_string(request_parameters, '$.attributeValue') like '%"AWS": "*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_sns_topics_subscription_deletions" {
  title           = "Detect SNS Topics Subscription Deletions"
  description     = "Detect when an endpoint is unsubscribed from an SNS topic to check for disruptions to message delivery, which could impact applications or services relying on notifications."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sns_topics_subscription_deletions

  tags = merge(local.cloudtrail_log_detection_sns_common_tags, {
    mitre_attack_ids = "TA0040:T1531"
  })
}

query "cloudtrail_logs_detect_sns_topics_subscription_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_sns_topics_subscription_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'Unsubscribe'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates" {
  title           = "Detect SNS Topics Subscription Dead Letter Queue Updates"
  description     = "Detect when changes to the dead letter queue for an SNS subscription to check for abuse, such as redirecting failed notifications to unauthorized queues."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates

  tags = merge(local.cloudtrail_log_detection_sns_common_tags, {
    mitre_attack_ids = "TA0003:T1078"
  })
}

query "cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_sns_topics_subscription_dead_letter_queue_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetSubscriptionAttributes'
      and json_extract_string(request_parameters, '$.attributeName') = 'RedrivePolicy'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates" {
  title           = "Detect SNS Topics with Encryption Setting Updates"
  description     = "Detect SNS topics with encryption disabled to check for events where KMS keys are removed, potentially exposing sensitive log data to unauthorized access or tampering."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates

  tags = merge(local.cloudtrail_log_detection_cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_sns_topics_with_encryption_setting_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and json_extract_string(request_parameters, '$.attributeName') = 'KmsMasterKeyId'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
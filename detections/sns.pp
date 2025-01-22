locals {
  sns_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SNS"
  })
}

benchmark "sns_detections" {
  title       = "SNS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SNS events."
  type        = "detection"
  children = [
    detection.sns_topic_granted_public_access,
    detection.sns_topic_encryption_at_rest_disabled,
  ]

  tags = merge(local.sns_common_tags, {
    type    = "Benchmark"
  })
}

detection "sns_topic_granted_public_access" {
  title           = "SNS Topic Granted Public Access"
  description     = "Detect when public access was granted to an SNS topic, potentially allowing unauthorized access and exposing sensitive notifications to external entities."
  documentation   = file("./detections/docs/sns_topic_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sns_topic_granted_public_access

  tags = merge(local.sns_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

// Need to refactor the query to iterate the policy statements from the logs and check any of the statement have public access(Same as SQS Queue public access granted).
query "sns_topic_granted_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_queue_url}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and (request_parameters ->> 'attributeName') = 'Policy'
      and (request_parameters ->> 'attributeValue') like '%"Effect": "Allow"%'
      and (request_parameters ->> 'attributeValue') like '%"AWS": "*"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "sns_topic_encryption_at_rest_disabled" {
  title           = "SNS Topic Encryption at Rest Disabled"
  description     = "Detect when an SNS topic was updated with encryption at rest disabled, potentially exposing sensitive log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/sns_topic_encryption_at_rest_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.sns_topic_encryption_at_rest_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "sns_topic_encryption_at_rest_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_queue_url}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and (request_parameters ->> 'attributeName') = 'KmsMasterKeyId'
      and (request_parameters ->> 'attributeValue') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

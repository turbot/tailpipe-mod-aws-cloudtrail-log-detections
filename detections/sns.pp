locals {
  sns_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SNS"
  })

  detect_public_access_granted_to_sns_topics_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.topicArn')")
  detect_sns_topics_with_encryption_at_rest_disabled_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.topicArn')")
}

benchmark "sns_detections" {
  title       = "SNS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SNS events."
  type        = "detection"
  children = [
    # TODO: Re-add detection once query has the proper checks
    #detection.detect_public_access_granted_to_sns_topics,
    detection.detect_sns_topics_with_encryption_at_rest_disabled,
  ]

  tags = merge(local.sns_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_public_access_granted_to_sns_topics" {
  title           = "Detect Public Access Granted to SNS Topics"
  description     = "Detect when a public policy is added to an SNS topic to check for potential unauthorized access, which could expose sensitive notifications to external entities."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_sqs_queues_without_encryption_at_rest

  tags = merge(local.sns_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

// Need to refactor the query to iterate the policy statements from the logs and check any of the statement have public access.
query "detect_public_access_granted_to_sns_topics" {
  sql = <<-EOQ
    select
      ${local.detect_public_access_granted_to_sns_topics_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and json_extract_string(request_parameters, '$.attributeName') = 'Policy'
      and json_extract_string(request_parameters, '$.attributeValue') like '%"Effect": "Allow"%'
      and json_extract_string(request_parameters, '$.attributeValue') like '%"AWS": "*"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_sns_topics_with_encryption_at_rest_disabled" {
  title           = "Detect SNS Topics with Encryption at Rest Disabled"
  description     = "Detect SNS topics with encryption at rest disabled to check for events where KMS keys are removed, potentially exposing sensitive log data to unauthorized access or tampering."
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_sns_topics_with_encryption_at_rest_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_sns_topics_with_encryption_at_rest_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_sns_topics_with_encryption_at_rest_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sns.amazonaws.com'
      and event_name = 'SetTopicAttributes'
      and json_extract_string(request_parameters, '$.attributeName') = 'KmsMasterKeyId'
      and json_extract_string(request_parameters, '$.attributeValue') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

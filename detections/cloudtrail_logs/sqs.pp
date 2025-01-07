locals {

  cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.queueUrl')")
  cloudtrail_logs_detect_public_access_granted_to_sqs_queues_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.queueUrl')")
  cloudtrail_logs_detect_sqs_queues_with_dlq_disabled_sql_columns          = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.queueUrl')")
}

benchmark "cloudtrail_logs_sqs_detections" {
  title       = "SQS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SQS events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest,
    detection.cloudtrail_logs_detect_public_access_granted_to_sqs_queues,
    detection.cloudtrail_logs_detect_sqs_queues_with_dlq_disabled,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/SQS"
  })
}

detection "cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest" {
  title           = "Detect SQS Queues Created Without Encryption at Rest"
  description     = "Detect when AWS SQS queues are created or updated without encryption at rest enabled. Unencrypted queues may expose sensitive data to unauthorized access or data exfiltration."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

query "cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_sqs_queues_without_encryption_at_rest_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('CreateQueue', 'SetQueueAttributes')
      -- Check for missing KMS key ID, which means no encryption at rest
      and (json_extract_string(request_parameters, '$.attributes.KmsMasterKeyId') is null 
      or json_extract_string(request_parameters, '$.attributes.KmsMasterKeyId') = '')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_public_access_granted_to_sqs_queues" {
  title           = "Detect Public Access Granted to SQS Queues"
  description     = "Detect when an SQS queue policy is modified to grant public access. Publicly accessible SQS queues may expose sensitive data or allow unauthorized actions like message injection or tampering."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_sqs_queues

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

query "cloudtrail_logs_detect_public_access_granted_to_sqs_queues" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_sqs_queues_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sqs.amazonaws.com'
      and event_name = 'SetQueueAttributes'
      and (
        -- Detect wildcard principals granting public access
        json_extract_string(request_parameters, '$.attributes.Policy') like '%"Principal":"*"%' 

        -- Detect AWS wildcard principals granting cross-account access
        or json_extract_string(request_parameters, '$.attributes.Policy') like '%"Principal":{"AWS":"*"}%'
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_sqs_queues_with_dlq_disabled" {
  title           = "Detect SQS Queues with Dead Letter Queue (DLQ) Configuration Disabled"
  description     = "Detect when an SQS queue is created or updated without a Dead Letter Queue (DLQ) configuration. DLQ configuration helps retain failed messages, and its absence can lead to message loss and missed error handling opportunities."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_sqs_queues_with_dlq_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "cloudtrail_logs_detect_sqs_queues_with_dlq_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_sqs_queues_with_dlq_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'sqs.amazonaws.com'
      and event_name in ('CreateQueue', 'SetQueueAttributes')
      and (
        -- Check if the RedrivePolicy (DLQ configuration) is missing or empty
        json_extract_string(request_parameters, '$.attributes.RedrivePolicy') is null
        or json_extract_string(request_parameters, '$.attributes.RedrivePolicy') = ''
      )
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}


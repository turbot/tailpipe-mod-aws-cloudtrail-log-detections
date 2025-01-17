locals {
  sqs_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/SQS"
  })
}

benchmark "sqs_detections" {
  title       = "SQS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for SQS events."
  type        = "detection"
  children = [
    detection.sqs_queue_created_with_encryption_at_rest_disabled,
    # TODO: Re-add detection once query has the proper checks
    #detection.detect_public_access_granted_to_sqs_queues,
    detection.detect_sqs_queues_with_dlq_disabled,
  ]

  tags = merge(local.sqs_common_tags, {
    type    = "Benchmark"
  })
}

detection "sqs_queue_created_with_encryption_at_rest_disabled" {
  title           = "SQS Queues Created with Encryption at Rest Disabled"
  description     = "Detect when an AWS SQS queue was created or updated without encryption at rest enabled to check for potential risks of unauthorized access or data exfiltration due to unencrypted data."
  documentation   = file("./detections/docs/sqs_queue_created_with_encryption_at_rest_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.sqs_queue_created_with_encryption_at_rest_disabled

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

query "sqs_queue_created_with_encryption_at_rest_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_queue_url}
    from
      aws_cloudtrail_log
    where
      event_name in ('CreateQueue', 'SetQueueAttributes')
      -- Check for missing KMS key ID, which means no encryption at rest
      and (json_extract_string(request_parameters, '$.attributes.KmsMasterKeyId') is null
      or json_extract_string(request_parameters, '$.attributes.KmsMasterKeyId') = '')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_public_access_granted_to_sqs_queues" {
  title           = "Detect Public Access Granted to SQS Queues"
  description     = "Detect when an SQS queue policy is modified to grant public access. Publicly accessible SQS queues may expose sensitive data or allow unauthorized actions like message injection or tampering."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_public_access_granted_to_sqs_queues

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

query "detect_public_access_granted_to_sqs_queues" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_queue_url}
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
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_sqs_queues_with_dlq_disabled" {
  title           = "Detect SQS Queues with Dead Letter Queue (DLQ) Configuration Disabled"
  description     = "Detect when an SQS queue is created or updated without a Dead Letter Queue (DLQ) configuration. DLQ configuration helps retain failed messages, and its absence can lead to message loss and missed error handling opportunities."
  documentation   = file("./detections/docs/detect_sqs_queues_with_dlq_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.detect_sqs_queues_with_dlq_disabled

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "detect_sqs_queues_with_dlq_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_queue_url}
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
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


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
    detection.sqs_queue_public_access_granted,
    detection.sqs_queue_dlq_disabled,
  ]

  tags = merge(local.sqs_common_tags, {
    type    = "Benchmark"
  })
}

detection "sqs_queue_created_with_encryption_at_rest_disabled" {
  title           = "SQS Queues Created with Encryption at Rest Disabled"
  description     = "Detect when an AWS SQS queue was created or updated with encryption at rest disabled to check for potential risks of unauthorized access or data exfiltration due to unencrypted data."
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
      event_name = 'CreateQueue'
      -- Check for missing KMS key ID, which means no encryption at rest
      and (request_parameters -> 'attributes' ->> 'KmsMasterKeyId') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "sqs_queue_public_access_granted" {
  title           = "SQS Queue Public Access Granted"
  description     = "Detect when an SQS queue policy was modified to grant public access, which may expose sensitive data or allow unauthorized actions like message injection or tampering."
  documentation   = file("./detections/docs/sqs_queue_public_access_granted.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sqs_queue_public_access_granted

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

// Cross check to find a way to iterate through the Policy statements 
// (select request_parameters -> 'attributes' -> 'Policy' -> 'Statement' from aws_cloudtrail_log where event_name = 'SetQueueAttributes';) 
// in the query for more accurate validation.

// The query "select request_parameters -> 'attributes' ->> 'Policy' from aws_cloudtrail_log where event_name = 'SetQueueAttributes';" 
// returns a stringified JSON.

// While we can successfully cast the stringified JSON into a JSON object, 
// attempting to iterate through the JSON array of objects results in an empty column value.

/*
 select request_parameters -> 'attributes' -> 'Policy' -> 'Statement'  from aws_cloudtrail_log where event_name = 'SetQueueAttributes';
┌─────────────────────────────────────────────────────────────────────┐
│ (((request_parameters -> 'attributes') -> 'Policy') -> 'Statement') │
│                                json                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│                                                                     │
│                                                                     │
│                                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
*/
query "sqs_queue_public_access_granted" {
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
        (request_parameters -> 'attributes' ->> 'Policy') like '%"Principal":"*"%' 

        -- Detect AWS wildcard principals granting cross-account access
        or (request_parameters -> 'attributes' ->> 'Policy') like '%"Principal":{"AWS":"*"}%'
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "sqs_queue_dlq_disabled" {
  title           = "SQS Queue DLQ Disabled"
  description     = "Detect when an SQS queue was created or updated without a Dead Letter Queue (DLQ) configuration, which may lead to message loss and missed error handling opportunities."
  documentation   = file("./detections/docs/sqs_queue_dlq_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.sqs_queue_dlq_disabled

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "sqs_queue_dlq_disabled" {
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
        (request_parameters -> 'attributes' ->> 'RedrivePolicy') is null
        or (request_parameters -> 'attributes' ->> 'RedrivePolicy') = ''
      )
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


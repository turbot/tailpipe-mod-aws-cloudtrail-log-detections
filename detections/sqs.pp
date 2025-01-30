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
    detection.sqs_queue_dlq_disabled,
    detection.sqs_queue_granted_public_access,
  ]

  tags = merge(local.sqs_common_tags, {
    type    = "Benchmark"
  })
}

detection "sqs_queue_created_with_encryption_at_rest_disabled" {
  title           = "SQS Queue Created with Encryption at Rest Disabled"
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
      ${local.detection_sql_resource_column_request_parameters_or_response_elements_queue_url}
    from
      aws_cloudtrail_log
    where
      event_name = 'CreateQueue'
      and (request_parameters -> 'attributes' ->> 'KmsMasterKeyId') is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "sqs_queue_granted_public_access" {
  title           = "SQS Queue Granted Public Access"
  description     = "Detect when an SQS queue policy was modified to grant public access, potentially exposing sensitive data or allowing unauthorized actions like message injection or tampering."
  documentation   = file("./detections/docs/sqs_queue_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.sqs_queue_granted_public_access

  tags = merge(local.sqs_common_tags, {
    mitre_attack_ids = "TA0010:T1567.002"
  })
}

query "sqs_queue_granted_public_access" {
  sql = <<-EOQ
    with policy as (
      select
        *,
        unnest(
          from_json((request_parameters -> 'attributes' ->> 'Policy' -> 'Statement'), '["JSON"]')
        ) as statement_item,
      from
        aws_cloudtrail_log
      where
        event_source = 'sqs.amazonaws.com'
        and event_name = 'SetQueueAttributes'
        and (request_parameters -> 'attributes' ->> 'Policy') != ''
    )
    select
      ${local.detection_sql_resource_column_request_parameters_or_response_elements_queue_url}
    from
      policy
    where
      (statement_item ->> 'Effect') = 'Allow'
      and ((json_contains((statement_item -> 'Principal'), '{"AWS":"*"}') ) or ((statement_item ->> 'Principal') = '*'))
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
      ${local.detection_sql_resource_column_request_parameters_or_response_elements_queue_url}
    from
      aws_cloudtrail_log
    where
      event_source = 'sqs.amazonaws.com'
      and event_name = 'SetQueueAttributes'
      and (request_parameters -> 'attributes' ->> 'RedrivePolicy') = ''
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


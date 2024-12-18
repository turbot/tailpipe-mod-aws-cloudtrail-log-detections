locals {
  cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_cloudtrail_detections" {
  title       = "CloudTrail Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's CloudTrail logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_lambda_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_encryption_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_kms_key_updated,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_bucket_modified,
    detection.cloudtrail_logs_detect_cloudtrail_trails_with_global_service_logging_disabled,
    detection.cloudtrail_logs_detect_cloudtrail_trail_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/CloudTrail"
  })
}

detection "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  title       = "Detect CloudTrail Trails Updates"
  description = "Detect changes to CloudTrail trails to check if logging was stopped."
  severity    = "medium"
  documentation        = file("./detections/docs/cloudtrail_logs_detect_cloudtrail_trail_updates.md")
  query       = query.cloudtrail_logs_detect_cloudtrail_trail_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562:001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trail_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name in ('DeleteTrail', 'StopLogging', 'UpdateTrail')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_disabled" {
  title       = "Detect CloudTrail Trails with S3 Logging Disabled"
  description = "Identify changes to event selectors where logging for S3 data events is disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and request_parameters ->> 'eventSelectors' not like '%"DataResourceType":"AWS::S3::Object"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_lambda_logging_disabled" {
  title       = "Detect CloudTrail Trails with Lambda Logging Disabled"
  description = "Identify changes to event selectors where logging for Lambda invocations is disabled."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_lambda_logging_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_lambda_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and request_parameters ->> 'eventSelectors' not like '%"DataResourceType":"AWS::Lambda::Function"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_encryption_disabled" {
  title       = "Detect CloudTrail Trails with Encryption Disabled"
  description = "Identify events where a CloudTrail trail's KMS key is removed, potentially disabling encryption."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_encryption_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and request_parameters->>'KmsKeyId' is null
      and response_elements->>'trailARN' is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_kms_key_updated" {
  title       = "Detect CloudTrail Trails with KMS Key Updated"
  description = "Identify changes to the KMS key used for encrypting CloudTrail logs, potentially redirecting logs to an untrusted key."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_kms_key_updated

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_kms_key_updated" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and request_parameters->>'KmsKeyId' is not null
      and response_elements->>'trailARN' is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_bucket_modified" {
  title       = "Detect CloudTrail Trails with S3 Logging Bucket Modified"
  description = "Identify events where the S3 bucket used for storing CloudTrail logs is changed, potentially redirecting logs to an unauthorized location."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_bucket_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_s3_logging_bucket_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and request_parameters->>'S3BucketName' is not null
      and response_elements->>'trailARN' is not null
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trails_with_global_service_logging_disabled" {
  title       = "Detect CloudTrail Trails with Global Service Logging Disabled"
  description = "Identify changes to CloudTrail trails where logging for global services is disabled."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_cloudtrail_trails_with_global_service_logging_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trails_with_global_service_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and request_parameters->>'IncludeGlobalServiceEvents' = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_cloudtrail_trail_deletions" {
  title       = "Detect CloudTrail Trails Deletions"
  description = "Identify events where a CloudTrail trail is deleted, potentially disabling logging for critical activities."
  severity    = "critical"
  query       = query.cloudtrail_logs_detect_cloudtrail_trail_deletion

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_cloudtrail_trail_deletion" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'DeleteTrail'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}



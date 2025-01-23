locals {
  cloudtrail_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudTrail"
  })

}

benchmark "cloudtrail_detections" {
  title       = "CloudTrail Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudTrail events."
  type        = "detection"
  children = [
    detection.cloudtrail_trail_global_service_logging_disabled,
    detection.cloudtrail_trail_kms_key_updated,
    detection.cloudtrail_trail_logging_stopped,
    detection.cloudtrail_trail_s3_logging_bucket_updated,
  ]

  tags = merge(local.cloudtrail_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_trail_logging_stopped" {
  title           = "CloudTrail Trail Logging Stopped"
  description     = "detect when a CloudTrail trail's logging was stopped to check for unauthorized changes that could reduce visibility into critical AWS activity, potentially hindering threat detection and compliance efforts."
  documentation   = file("./detections/docs/cloudtrail_trail_logging_stopped.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_logging_stopped

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001,TA0002:T1059.009"
  })
}


query "cloudtrail_trail_logging_stopped" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'StopLogging'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

# Restricting to CLI-based events, as console requests show all fields while CLI only shows updated fields.
detection "cloudtrail_trail_kms_key_updated" {
  title           = "CloudTrail Trail KMS Key Updated"
  description     = "Detect when a CloudTrail trail was updated with a new KMS key to check for changes that could expose log data to unauthorized access or tampering, potentially compromising log integrity and security."
  documentation   = file("./detections/docs/cloudtrail_trail_kms_key_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_kms_key_updated

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_kms_key_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters ->> 'KmsKeyId') is not null
      and (response_elements ->> 'trailARN') is not null
      -- here we exclude console-based events by requiring 'session_credential_from_console' to be null, because console requests show all fields while CLI only shows updated fields.
      and session_credential_from_console is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

# Restricting to CLI-based events, as console requests show all fields while CLI only shows updated fields.
detection "cloudtrail_trail_s3_logging_bucket_updated" {
  title           = "CloudTrail Trail S3 Logging Bucket Updated"
  description     = "Detect when a CloudTrail trail was updated with a new S3 logging bucket to check for changes that could expose log data to unauthorized access or tampering, potentially compromising log integrity and security."
  documentation   = file("./detections/docs/cloudtrail_trail_s3_logging_bucket_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_s3_logging_bucket_updated

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_s3_logging_bucket_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters ->> 's3BucketName') is not null
      and (response_elements ->> 'trailARN') is not null
      -- here we exclude console-based events by requiring 'session_credential_from_console' to be null, because console requests show all fields while CLI only shows updated fields.
      and session_credential_from_console is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

# Restricting to CLI-based events, as console requests show all fields while CLI only shows updated fields.
detection "cloudtrail_trail_global_service_logging_disabled" {
  title           = "CloudTrail Trail Global Service Logging Disabled"
  description     = "Detect when a CloudTrail trail was created without global service logging to check for potential misconfigurations or unauthorized changes that could expose log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/cloudtrail_trail_global_service_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_global_service_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_global_service_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters -> 'includeGlobalServiceEvents') = 'false'
      -- here we exclude console-based events by requiring 'session_credential_from_console' to be null, because console requests show all fields while CLI only shows updated fields.
      and session_credential_from_console is null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

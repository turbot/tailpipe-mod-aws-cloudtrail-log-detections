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
    detection.cloudtrail_trails_encryption_disabled,
    detection.cloudtrail_trails_global_service_logging_disabled,
    detection.cloudtrail_trails_kms_key_updated,
    detection.cloudtrail_trails_lambda_logging_disabled,
    detection.cloudtrail_trails_logging_stopped,
    detection.cloudtrail_trails_s3_logging_bucket_modified,
    detection.cloudtrail_trails_s3_logging_disabled,
  ]

  tags = merge(local.cloudtrail_common_tags, {
    type = "Benchmark"
  })
}

detection "cloudtrail_trails_logging_stopped" {
  title       = "CloudTrail Trails Logging Stopped"
  description = "Detect when CloudTrail trail logging was stopped to check for changes that could reduce visibility into critical AWS API activity, potentially obscuring unauthorized access or configuration changes."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_logging_stopped.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_logging_stopped

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001,TA0002:T1059.009"
  })
}


query "cloudtrail_trails_logging_stopped" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
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

detection "cloudtrail_trails_s3_logging_disabled" {
  title       = " CloudTrail Trails S3 Logging Disabled"
  description = "Detect when S3 logging for CloudTrail trails were disabled to check for changes that could reduce visibility into critical S3 data events, hindering the ability to detect unauthorized access or data exfiltration."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_s3_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_s3_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_s3_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and (request_parameters ->> 'eventSelectors') not like '%"DataResourceType":"AWS::S3::Object"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trails_lambda_logging_disabled" {
  title       = "CloudTrail Trails Lambda Logging Disabled"
  description = "Detect when Lambda logging for CloudTrail trails was disabled to check for changes that could reduce visibility into Lambda invocation events, potentially obscuring unauthorized activity or misconfigurations."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_lambda_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_lambda_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_lambda_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and (request_parameters ->> 'eventSelectors') not like '%"DataResourceType":"AWS::Lambda::Function"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trails_encryption_disabled" {
  title       = "CloudTrail Trails Encryption Disabled"
  description = "Detect when encryption for CloudTrail trails were disabled to check for events where KMS keys are removed, potentially exposing sensitive log data to unauthorized access or tampering."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_encryption_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_encryption_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters ->> 'KmsKeyId') is null
      and (response_elements ->> 'trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trails_kms_key_updated" {
  title       = "CloudTrail Trails KMS Key Updated"
  description = "Detect changes to the KMS key used for encrypting CloudTrail logs to check for potential misconfigurations or unauthorized updates that could redirect log encryption to an untrusted or compromised key."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_kms_key_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_kms_key_updated

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_kms_key_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters ->> 'KmsKeyId') is not null
      and (response_elements ->> 'trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trails_s3_logging_bucket_modified" {
  title       = "CloudTrail Trails S3 Logging Bucket Modified"
  description = "Detect changes to the S3 bucket used for storing CloudTrail logs to check for events that could redirect log data to an unauthorized or insecure location, compromising log integrity and security."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_s3_logging_bucket_modified.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_s3_logging_bucket_modified

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_s3_logging_bucket_modified" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and (request_parameters ->> 'S3BucketName') is not null
      and (response_elements ->> 'trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trails_global_service_logging_disabled" {
  title       = "CloudTrail Trails Global Service Logging Disabled"
  description = "Detect when global service logging for CloudTrail trails was disabled to check for changes that could reduce visibility into critical global service activity, potentially hindering threat detection and compliance efforts."
  # documentation   = file("./detections/docs/detect_cloudtrail_trails_with_global_service_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trails_global_service_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trails_global_service_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_cloudtrail_name}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and (request_parameters ->> 'IncludeGlobalServiceEvents') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

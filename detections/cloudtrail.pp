locals {
  cloudtrail_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/CloudTrail"
  })

  detect_cloudtrail_trail_updates_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudtrail_detections" {
  title       = "CloudTrail Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for CloudTrail events."
  type        = "detection"
  children = [
    detection.detect_cloudtrail_trails_with_encryption_disabled,
    detection.detect_cloudtrail_trails_with_global_service_logging_disabled,
    detection.detect_cloudtrail_trails_with_kms_key_updated,
    detection.detect_cloudtrail_trails_with_lambda_logging_disabled,
    detection.detect_cloudtrail_trails_with_logging_stopped,
    detection.detect_cloudtrail_trails_with_s3_logging_bucket_modified,
    detection.detect_cloudtrail_trails_with_s3_logging_disabled,
  ]

  tags = merge(local.cloudtrail_common_tags, {
    type = "Benchmark"
  })
}

detection "detect_cloudtrail_trails_with_logging_stopped" {
  title           = "Detect CloudTrail Trails with Logging Stopped"
  description     = "Detect CloudTrail trails with logging stopped to check for changes that could reduce visibility into critical AWS API activity, potentially obscuring unauthorized access or configuration changes."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_logging_stopped.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_logging_stopped

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001,TA0002:T1059.009"
  })
}


query "detect_cloudtrail_trails_with_logging_stopped" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
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

detection "detect_cloudtrail_trails_with_s3_logging_disabled" {
  title           = "Detect CloudTrail Trails with S3 Logging Disabled"
  description     = "Detect CloudTrail trails with S3 logging disabled to check for changes that could reduce visibility into critical S3 data events, hindering the ability to detect unauthorized access or data exfiltration."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_s3_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_s3_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_s3_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and json_extract_string(request_parameters, '$.eventSelectors') not like '%"DataResourceType":"AWS::S3::Object"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudtrail_trails_with_lambda_logging_disabled" {
  title           = "Detect CloudTrail Trails with Lambda Logging Disabled"
  description     = "Detect CloudTrail trails with Lambda logging disabled to check for changes that could reduce visibility into Lambda invocation events, potentially obscuring unauthorized activity or misconfigurations."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_lambda_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_lambda_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_lambda_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and json_extract_string(request_parameters, '$.eventSelectors') not like '%"DataResourceType":"AWS::Lambda::Function"%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudtrail_trails_with_encryption_disabled" {
  title           = "Detect CloudTrail Trails with Encryption Disabled"
  description     = "Detect CloudTrail trails with encryption disabled to check for events where KMS keys are removed, potentially exposing sensitive log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_encryption_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_encryption_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and json_extract_string(request_parameters, '$.KmsKeyId') is null
      and json_extract_string(response_elements, '$.trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudtrail_trails_with_kms_key_updated" {
  title           = "Detect CloudTrail Trails with KMS Key Updated"
  description     = "Detect changes to the KMS key used for encrypting CloudTrail logs to check for potential misconfigurations or unauthorized updates that could redirect log encryption to an untrusted or compromised key."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_kms_key_updated.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_kms_key_updated

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_kms_key_updated" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and json_extract_string(request_parameters, '$.KmsKeyId') is not null
      and json_extract_string(response_elements, '$.trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudtrail_trails_with_s3_logging_bucket_modified" {
  title           = "Detect CloudTrail Trails with S3 Logging Bucket Modified"
  description     = "Detect changes to the S3 bucket used for storing CloudTrail logs to check for events that could redirect log data to an unauthorized or insecure location, compromising log integrity and security."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_s3_logging_bucket_modified.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_s3_logging_bucket_modified

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_s3_logging_bucket_modified" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'UpdateTrail'
      and json_extract_string(request_parameters, '$.S3BucketName') is not null
      and json_extract_string(response_elements, '$.trailARN') is not null
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "detect_cloudtrail_trails_with_global_service_logging_disabled" {
  title           = "Detect CloudTrail Trails with Global Service Logging Disabled"
  description     = "Detect CloudTrail trails with global service logging disabled to check for changes that could reduce visibility into critical global service activity, potentially hindering threat detection and compliance efforts."
  documentation   = file("./detections/docs/detect_cloudtrail_trails_with_global_service_logging_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_cloudtrail_trails_with_global_service_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "detect_cloudtrail_trails_with_global_service_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_cloudtrail_trail_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'cloudtrail.amazonaws.com'
      and event_name = 'PutEventSelectors'
      and json_extract_string(request_parameters, '$.IncludeGlobalServiceEvents') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

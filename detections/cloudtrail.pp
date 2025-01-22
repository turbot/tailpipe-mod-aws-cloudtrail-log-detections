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
    detection.cloudtrail_trail_encryption_disabled,
    detection.cloudtrail_trail_global_service_logging_disabled,
    detection.cloudtrail_trail_kms_key_updated,
    detection.cloudtrail_trail_lambda_logging_disabled,
    detection.cloudtrail_trail_logging_stopped,
    detection.cloudtrail_trail_s3_logging_bucket_modified,
    detection.cloudtrail_trail_s3_logging_disabled,
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

detection "cloudtrail_trail_s3_logging_disabled" {
  title           = " CloudTrail Trail S3 Logging Disabled"
  description     = "Detect when a CloudTrail trail was created without S3 logging to check for potential misconfigurations or unauthorized changes that could expose log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/cloudtrail_trail_s3_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_s3_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_s3_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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

detection "cloudtrail_trail_lambda_logging_disabled" {
  title           = "CloudTrail Trail Lambda Logging Disabled"
  description     = "Detect when a CloudTrail trail was created without Lambda logging to check for potential misconfigurations or unauthorized changes that could expose log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/cloudtrail_trail_lambda_logging_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_lambda_logging_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_lambda_logging_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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

detection "cloudtrail_trail_encryption_disabled" {
  title           = "CloudTrail Trail Encryption Disabled"
  description     = "Detect when a CloudTrail trail was created without encryption to check for potential misconfigurations or unauthorized changes that could expose log data to unauthorized access or tampering."
  documentation   = file("./detections/docs/cloudtrail_trail_encryption_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_encryption_disabled

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_encryption_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_trail_s3_logging_bucket_modified" {
  title           = "CloudTrail Trail S3 Logging Bucket Modified"
  description     = "Detect when a CloudTrail trail was updated with a new S3 logging bucket to check for changes that could expose log data to unauthorized access or tampering, potentially compromising log integrity and security."
  documentation   = file("./detections/docs/cloudtrail_trail_s3_logging_bucket_modified.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.cloudtrail_trail_s3_logging_bucket_modified

  tags = merge(local.cloudtrail_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_trail_s3_logging_bucket_modified" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
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
      and event_name = 'PutEventSelectors'
      and (request_parameters ->> 'IncludeGlobalServiceEvents') = 'false'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

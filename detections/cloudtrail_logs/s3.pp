locals {
  cloudtrail_logs_detect_s3_bucket_deleted_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_object_deleted_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_bucket_policy_public_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_tool_uploads_sql_columns           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_data_archiving_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_s3_detections" {
  title       = "CloudTrail Log S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's S3 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_s3_bucket_deleted,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modified,
    detection.cloudtrail_logs_detect_s3_tool_uploads,
    detection.cloudtrail_logs_detect_s3_data_archiving,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/S3"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_deleted" {
  title       = "Detect S3 Bucket Deleted"
  description = "Detect when an S3 Bucket is deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_deleted

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_object_deleted" {
  title       = "Detect S3 Object Deleted"
  description = "Detect when S3 Object, is deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_object_deleted

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_modified" {
  title       = "Detect S3 Buckets Policy Modified"
  description = "Detect when S3 buckets policy, is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_policy_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_public" {
  title       = "Detect S3 Buckets Policy Change to Allow Public Access"
  description = "Detect when S3 buckets policy is modified to allow public access."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_s3_bucket_policy_public

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_s3_tool_uploads" {
  title       = "Detect Lateral Tool Transfer"
  description = "Detect transfer of malicious tools or binaries between resources."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_tool_uploads.md")
  query       = query.cloudtrail_logs_detect_s3_tool_uploads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1570"
  })
}

detection "cloudtrail_logs_detect_s3_data_archiving" {
  title       = "Detect Data Archiving for Collection"
  description = "Detect archiving of collected data using AWS services such as S3 or Glacier."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_data_archiving.md")
  query       = query.cloudtrail_logs_detect_s3_data_archiving

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1560.001"
  })
}

query "cloudtrail_logs_detect_s3_data_archiving" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_data_archiving_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'PutObject'
      and request_parameters.key like '%.zip%'
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_tool_uploads" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_tool_uploads_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutObject', 'CopyObject')
      and request_parameters.key like '%.exe%'
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteBucket'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_object_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_object_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteObject'
      and error_code is null
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_policy_modified" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('PutBucketPolicy', 'PutBucketAcl', 'PutBucketCors', 'PutBucketLifecycle', 'PutBucketReplication', 'DeleteBucketPolicy', 'DeleteBucketCors', 'DeleteBucketLifecycle', 'DeleteBucketReplication')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_policy_public" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_policy_public_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'PutBucketPolicy'
      and cast(request_parameters -> 'policy' as text) like '%"Principal":"*"%'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}
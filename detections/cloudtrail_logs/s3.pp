locals {
  cloudtrail_logs_detect_s3_bucket_deleted_sql_columns                           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_bucket_policy_modified_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_bucket_policy_public_sql_columns                     = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
}

benchmark "cloudtrail_logs_s3_detections" {
  title       = "CloudTrail Log S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's S3 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_s3_bucket_deleted,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modified,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/S3"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_deleted" {
  title       = "Detect S3 Buckets Deleted"
  description = "Detect when S3 Buckets policy or website is deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_deleted

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

query "cloudtrail_logs_detect_s3_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_deleted_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteBucket'
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
      and error_code is null
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
      and cast(request_parameters -> 'ipPermissions' as text) like '%"Principal":"*"%'
    order by
      event_time desc;
  EOQ
}
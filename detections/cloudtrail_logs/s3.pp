benchmark "cloudtrail_logs_s3_detections" {
  title       = "CloudTrail Log S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's S3 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_s3_bucket_deleted,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modified,
  ]
}

detection "cloudtrail_logs_detect_s3_bucket_deleted" {
  title       = "Detect S3 Bucket Deleted"
  description = "Detect a S3 Bucket, Policy, or Website was deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_deleted

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_modified" {
  title       = "Detect  S3 Bucket Policy Modified"
  description = "Detect when S3 bucket policy, is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_policy_modified

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
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
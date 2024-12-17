locals {
  cloudtrail_logs_detect_s3_bucket_deletions_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_object_deletions_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_bucket_policy_modifications_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_public_policy_added_to_s3_buckets_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_tool_uploads_sql_columns           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.bucketName")
  cloudtrail_logs_detect_s3_data_archives_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_s3_large_file_downloads_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
  cloudtrail_logs_detect_s3_object_compressed_uploads_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "cloudtrail_logs_s3_detections" {
  title       = "S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's S3 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_s3_bucket_deletions,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modifications,
    detection.cloudtrail_logs_detect_s3_tool_uploads,
    detection.cloudtrail_logs_detect_s3_data_archives,
    detection.cloudtrail_logs_detect_s3_large_file_downloads,
    detection.cloudtrail_logs_detect_s3_object_deletions,
    detection.cloudtrail_logs_detect_public_policy_added_to_s3_buckets,
    detection.cloudtrail_logs_detect_s3_object_compressed_uploads,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/S3"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_deletions" {
  title       = "Detect S3 Bucket Deletions"
  description = "Detect when an S3 Bucket is deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_object_deletions" {
  title       = "Detect S3 Object Deletions"
  description = "Detect when S3 Object, is deleted."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_object_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_modifications" {
  title       = "Detect S3 Buckets Policy Modifications"
  description = "Detect when S3 buckets policy, is modified."
  severity    = "low"
  query       = query.cloudtrail_logs_detect_s3_bucket_policy_modifications

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

detection "cloudtrail_logs_detect_public_policy_added_to_s3_buckets" {
  title       = "Detect S3 Buckets Policy Change to Allow Public Access"
  description = "Detect when S3 buckets policy is modified to allow public access."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_public_policy_added_to_s3_buckets

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_s3_tool_uploads" {
  title       = "Detect S3 Lateral Tool Transfer"
  description = "Detect transfer of malicious tools or binaries between resources."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_tool_uploads.md")
  query       = query.cloudtrail_logs_detect_s3_tool_uploads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1570"
  })
}

detection "cloudtrail_logs_detect_s3_data_archives" {
  title       = "Detect S3 Data Archiving for Collection"
  description = "Detect archiving of collected data using AWS S3 services."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_data_archives.md")
  query       = query.cloudtrail_logs_detect_s3_data_archives

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1560.001"
  })
}

detection "cloudtrail_logs_detect_s3_large_file_downloads" {
  title       = "Detect S3 Large Data Transfers"
  description = "Detect S3 unusually large data transfers indicative of exfiltration."
  severity    = "critical"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_large_file_downloads.md")
  query       = query.cloudtrail_logs_detect_s3_large_file_downloads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1530"
  })
}

detection "cloudtrail_logs_detect_s3_object_compressed_uploads" {
  title       = "Detect S3 Data Compression Before Exfiltration"
  description = "Detect S3 data compression operations in preparation for exfiltration."
  severity    = "medium"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_object_compressed_uploads.md")
  query       = query.cloudtrail_logs_detect_s3_object_compressed_uploads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1029"
  })
}

query "cloudtrail_logs_detect_s3_data_archives" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_data_archives_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'PutObject'
      and request_parameters.key like '%.zip%'
      ${local.cloudtrail_log_detections_where_conditions}
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
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteBucket'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_object_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_object_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'DeleteObject'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_bucket_policy_modifications" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_bucket_policy_modifications_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name in ('PutBucketPolicy', 'PutBucketAcl', 'PutBucketCors', 'PutBucketLifecycle', 'PutBucketReplication', 'DeleteBucketPolicy', 'DeleteBucketCors', 'DeleteBucketLifecycle', 'DeleteBucketReplication')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_public_policy_added_to_s3_buckets" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_policy_added_to_s3_buckets_sql_columns}
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

query "cloudtrail_logs_detect_s3_large_file_downloads" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_large_file_downloads_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'GetObject'
      and cast(request_parameters->>'size' as integer) > 104857600 -- Size greater than 100MB
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_s3_object_compressed_uploads" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_s3_object_compressed_uploads_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutObject', 'UploadPart')
      and request_parameters.compressionFormat is not null
      and (user_identity.type = 'IAMUser' or user_identity.type = 'AssumedRole')
    order by
      event_time desc;
  EOQ
}

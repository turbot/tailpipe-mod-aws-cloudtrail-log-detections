locals {
  cloudtrail_logs_detect_s3_bucket_deletions_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.bucketName')")
  cloudtrail_logs_detect_s3_bucket_policy_modifications_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.bucketName')")
  cloudtrail_logs_detect_public_access_granted_to_s3_buckets_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.bucketName')")
  cloudtrail_logs_detect_s3_tool_uploads_sql_columns           = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.bucketName')")
  cloudtrail_logs_detect_s3_data_archiving_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_s3_large_file_downloads_sql_columns   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_s3_object_compressed_uploads_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
}

benchmark "cloudtrail_logs_s3_detections" {
  title       = "S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's S3 logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_s3_bucket_deletions,
    detection.cloudtrail_logs_detect_s3_bucket_policy_modifications,
    detection.cloudtrail_logs_detect_s3_tool_uploads,
    detection.cloudtrail_logs_detect_s3_data_archiving,
    detection.cloudtrail_logs_detect_s3_large_file_downloads,
    detection.cloudtrail_logs_detect_public_access_granted_to_s3_buckets,
    detection.cloudtrail_logs_detect_s3_object_compressed_uploads,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/S3"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_deletions" {
  title           = "Detect S3 Bucket Deletions"
  description     = "Detect when an S3 bucket is deleted. Deleting an S3 bucket can lead to data loss, disrupt services relying on stored data, and may indicate malicious activity aimed at destroying critical information or disrupting operations."
  severity        = "low"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_s3_bucket_deletions

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

detection "cloudtrail_logs_detect_s3_bucket_policy_modifications" {
  title           = "Detect S3 Buckets Policy Modifications"
  description     = "Detect when an S3 bucket policy is modified. Changes to bucket policies can weaken security controls, potentially exposing data to unauthorized access or enabling data exfiltration."
  severity        = "low"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_s3_bucket_policy_modifications

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

detection "cloudtrail_logs_detect_public_access_granted_to_s3_buckets" {
  title           = "Detect Public Access Granted to S3 Buckets"
  description     = "Detect when an S3 bucket policy is modified to allow public access. Granting public access can expose sensitive data to unauthorized users, increasing the risk of data breaches, data exfiltration, or malicious exploitation."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_public_access_granted_to_s3_buckets

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

detection "cloudtrail_logs_detect_s3_tool_uploads" {
  title           = "Detect S3 Tool Uploads"
  description     = "Detect the upload of tools or binaries to S3 that may be used for lateral movement or malicious activity. Transferring malicious tools between resources via S3 can indicate preparation for further exploitation, persistence, or escalation within the environment."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_tool_uploads.md")
  query           = query.cloudtrail_logs_detect_s3_tool_uploads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0008:T1570"
  })
}

detection "cloudtrail_logs_detect_s3_data_archiving" {
  title           = "Detect S3 Data Archiving"
  description     = "Detect when data is archived in S3, which may indicate an attempt to store or package data for later exfiltration. Archiving large amounts of data can be part of a malicious workflow aimed at preparing data for transfer or long-term storage outside of standard security controls."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_data_archiving.md")
  query           = query.cloudtrail_logs_detect_s3_data_archiving

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0009:T1560.001"
  })
}

detection "cloudtrail_logs_detect_s3_large_file_downloads" {
  title           = "Detect S3 Large File Downloads"
  description     = "Detect unusually large data downloads from S3 buckets that may indicate potential data exfiltration. Large file downloads can be a sign of malicious activity, such as unauthorized data extraction by an external attacker or insider threat."
  severity        = "critical"
  display_columns = local.cloudtrail_log_detection_display_columns
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_large_file_downloads.md")
  query           = query.cloudtrail_logs_detect_s3_large_file_downloads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1530"
  })
}

detection "cloudtrail_logs_detect_s3_object_compressed_uploads" {
  title           = "Detect S3 Object Compressed Uploads"
  description     = "Detect when S3 objects are compressed before being uploaded or modified. Data compression may indicate preparation for data exfiltration, as attackers often compress data to facilitate faster transfer and minimize detection."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  # documentation = file("./detections/docs/cloudtrail_logs_detect_s3_object_compressed_uploads.md")
  query           = query.cloudtrail_logs_detect_s3_object_compressed_uploads

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0010:T1029"
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
      and json_extract_string(request_parameters, '$.key') like '%.zip%'
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
      and json_extract_string(request_parameters, '$.key') like '%.exe%'
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

query "cloudtrail_logs_detect_public_access_granted_to_s3_buckets" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_public_access_granted_to_s3_buckets_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_name = 'PutBucketPolicy'
      and json_extract_string(request_parameters, '$.policy') like '%"Principal":"*"%'
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
      and json_extract_string(request_parameters, '$.size')::int > 104857600 -- Size greater than 100MB
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
      and json_extract_string(request_parameters, '$.compressionFormat') is not null
      and (json_extract_string(user_identity, '$.type') = 'IAMUser' or json_extract_string(user_identity, '$.type') = 'AssumedRole')
    order by
      event_time desc;
  EOQ
}

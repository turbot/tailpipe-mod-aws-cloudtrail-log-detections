locals {
  s3_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/S3"
  })
}

benchmark "s3_detections" {
  title       = "S3 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for S3 events."
  type        = "detection"
  children = [
    detection.s3_bucket_block_public_access_disabled,
    detection.s3_bucket_deleted,
    detection.s3_bucket_policy_granted_public_access,
    detection.s3_bucket_policy_updated,
    detection.s3_large_file_downloaded,
  ]

  tags = merge(local.s3_common_tags, {
    type    = "Benchmark"
    service = "AWS/S3"
  })
}

detection "s3_bucket_deleted" {
  title           = "S3 Bucket Deleted"
  description     = "Detect when an S3 bucket was deleted. Deleting an S3 bucket can lead to data loss, disrupt services relying on stored data, and may indicate malicious activity aimed at destroying critical information or disrupting operations."
  documentation   = file("./detections/docs/s3_bucket_deleted.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.s3_bucket_deleted

  tags = merge(local.s3_common_tags, {
    mitre_attack_ids = "TA0040:T1485"
  })
}

query "s3_bucket_deleted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_bucket_name}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'DeleteBucket'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "s3_bucket_policy_updated" {
  title           = "S3 Bucket Policy Updated"
  description     = "Detect when an S3 bucket policy was updated. Changes to bucket policies can weaken security controls, potentially exposing data to unauthorized access or enabling data exfiltration."
  documentation   = file("./detections/docs/s3_bucket_policy_updated.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.s3_bucket_policy_updated

  tags = merge(local.s3_common_tags, {
    mitre_attack_ids = "TA0010:T1567"
  })
}

query "s3_bucket_policy_updated" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_bucket_name}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutBucketPolicy')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "s3_bucket_policy_granted_public_access" {
  title           = "S3 Bucket Policy Granted Public Access"
  description     = "Detect when public access was granted to an S3 bucket by modifying its policy. Granting public access through a bucket policy can expose sensitive data to unauthorized users, increasing the risk of data breaches, data exfiltration, or malicious exploitation."
  documentation   = file("./detections/docs/s3_bucket_policy_granted_public_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.s3_bucket_policy_granted_public_access

  tags = merge(local.s3_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0001:T1190"
  })
}

query "s3_bucket_policy_granted_public_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_bucket_name}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'PutBucketPolicy'
      and (json_contains(request_parameters -> 'bucketPolicy', '{"Principal": "*"}')
        or json_contains(request_parameters -> 'bucketPolicy', '{"Principal": {"AWS": "*"}}'))
      and json_contains(request_parameters -> 'bucketPolicy', '{"Effect": "Allow"}')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


detection "s3_bucket_block_public_access_disabled" {
  title           = "S3 Bucket Block Public Access Disabled"
  description     = "Detect when block public access setting was disabled for an S3 bucket. Granting public access can expose sensitive data to unauthorized users, increasing the risk of data breaches, data exfiltration, or malicious exploitation."
  documentation   = file("./detections/docs/s3_bucket_block_public_access_disabled.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.s3_bucket_block_public_access_disabled

  tags = merge(local.s3_common_tags, {
    mitre_attack_ids = "TA0005:T1070,TA0001:T1190"
    recommended      = "true"
  })
}

query "s3_bucket_block_public_access_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_bucket_name}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'PutBucketPublicAccessBlock'
      and ((request_parameters -> 'PublicAccessBlockConfiguration' -> 'RestrictPublicBuckets') = false
      or (request_parameters -> 'PublicAccessBlockConfiguration' -> 'BlockPublicPolicy') = false
      or (request_parameters -> 'PublicAccessBlockConfiguration' -> 'BlockPublicAcls') = false
      or (request_parameters -> 'PublicAccessBlockConfiguration' -> 'IgnorePublicAcls') = false)
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "s3_large_file_downloaded" {
  title           = "S3 Large File Downloaded"
  description     = "Detect when a large file was downloaded from an S3 bucket. Unusually large file downloads may indicate potential data exfiltration, such as unauthorized data extraction by an external attacker or insider threat."
  severity        = "low"
  display_columns = local.detection_display_columns
  documentation   = file("./detections/docs/s3_large_file_downloaded.md")
  query           = query.s3_large_file_downloaded

  tags = merge(local.s3_common_tags, {
    mitre_attack_ids = "TA0010:T1530"
  })
}

query "s3_large_file_downloaded" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_name}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name = 'GetObject'
      and (request_parameters -> 'size')::int > 104857600 -- Size greater than 100MB
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


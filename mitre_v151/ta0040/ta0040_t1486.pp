locals {
  mitre_v151_ta0040_t1486_common_tags = merge(local.mitre_v151_ta0040_common_tags, {
    mitre_technique_id = "T1486"
  })

  cloudtrail_logs_detect_data_encryption_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.name")
}

benchmark "mitre_v151_ta0040_t1486" {
  title         = "T1486 Data Encrypted for Impact"
  type          = "detection"
  # documentation = file("./mitre_v151/docs/ta0040_t1486.md")
  children = [
    detection.cloudtrail_logs_detect_data_encryption
  ]

  tags = local.mitre_v151_ta0040_t1486_common_tags
}

detection "cloudtrail_logs_detect_data_encryption" {
  title       = "Detect Data Encryption for Impact"
  description = "Detect attempts to enable encryption for S3 buckets or EBS volumes."
  severity    = "high"
  # documentation = file("./detections/docs/cloudtrail_logs_detect_data_encryption.md")
  query       = query.cloudtrail_logs_detect_data_encryption

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1486"
  })
}

query "cloudtrail_logs_detect_data_encryption" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_data_encryption_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 's3.amazonaws.com'
      and event_name in ('PutBucketEncryption', 'PutObject')
      and error_code is null
    order by
      event_time desc;
  EOQ
}

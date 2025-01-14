locals {
  kms_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/KMS"
  })

  detect_kms_key_deletions_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.keyId')")
}

benchmark "kms_detections" {
  title       = "KMS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for KMS events."
  type        = "detection"
  children    = [
    detection.detect_kms_key_deletions,
  ]

  tags = merge(local.kms_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_kms_key_deletions" {
  title           = "Detect AWS KMS Key Deletions"
  description     = "Detect when an AWS KMS key is scheduled for deletion. Deleting a KMS key can render encrypted data permanently inaccessible, disrupt critical services, and impair data protection mechanisms. Unauthorized deletions may indicate an attempt to destroy evidence or disable security controls."
  documentation   = file("./detections/docs/detect_kms_key_deletions.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_kms_key_deletions

  tags = merge(local.kms_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "detect_kms_key_deletions" {
  sql = <<-EOQ
    select
      ${local.detect_kms_key_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'kms.amazonaws.com'
      and event_name = 'ScheduleKeyDeletion'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

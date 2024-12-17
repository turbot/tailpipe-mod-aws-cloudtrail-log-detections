locals {
  cloudtrail_log_detection_kms_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/KMS"
  })

  cloudtrail_logs_detect_kms_key_deletions_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "request_parameters.keyId")
}

benchmark "cloudtrail_logs_kms_detections" {
  title       = "KMS"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for KMS events."
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_kms_key_deletions,
  ]

  tags = merge(local.cloudtrail_log_detection_kms_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_kms_key_deletions" {
  title       = "Detect AWS KMS Keys Deletion"
  description = "Detect when a KMS key is scheduled for deletion."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_kms_key_deletions

  tags = merge(local.cloudtrail_log_detection_kms_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "cloudtrail_logs_detect_kms_key_deletions" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_kms_key_deletions_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'kms.amazonaws.com'
      and event_name = 'ScheduleKeyDeletion'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

locals {
  kms_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/KMS"
  })
}

benchmark "kms_detections" {
  title       = "KMS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for KMS events."
  type        = "detection"
  children    = [
    detection.kms_key_deletion_scheduled,
  ]

  tags = merge(local.kms_common_tags, {
    type    = "Benchmark"
  })
}

detection "kms_key_deletion_scheduled" {
  title           = "KMS Key Scheduled Deletion"
  description     = "Detect when KMS key was scheduled for deletion. This action could render encrypted data permanently inaccessible, disrupt critical services, or impair data protection mechanisms. Unauthorized scheduling of deletion may indicate an attempt to destroy evidence or disable security controls."
  documentation   = file("./detections/docs/kms_key_deletion_scheduled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.kms_key_deletion_scheduled

  tags = merge(local.kms_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "kms_key_deletion_scheduled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_key_id}
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

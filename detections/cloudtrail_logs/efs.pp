locals {
  cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled_sql_columns  = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.fileSystemId, request_parameters.mountTargetId)")
}

benchmark "cloudtrail_logs_efs_detections" {
  title       = "EFS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EFS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/EFS"
  })
}

detection "cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled" {
  title       = "Detect EFS File Systems with Backup Policy Disabled"
  description = "Identify events where backup policies are disabled for EFS file systems, potentially leaving data unprotected."
  severity    = "high"
  query       = query.cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = "TA0040:T1562.001"
  })
}

query "cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_efs_file_systems_with_backup_policy_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name = 'PutBackupPolicy'
      and request_parameters->>'BackupPolicyStatus' = 'DISABLED'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

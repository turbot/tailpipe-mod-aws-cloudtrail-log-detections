locals {
  efs_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EFS"
  })

}

benchmark "efs_detections" {
  title       = "EFS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EFS events"
  type        = "detection"
  children = [
    detection.efs_file_system_backup_policy_disabled,
  ]

  tags = merge(local.efs_common_tags, {
    type = "Benchmark"
  })
}

detection "efs_file_system_backup_policy_disabled" {
  title           = "EFS File System Backup Policy Disabled"
  description     = "Detect when an EFS file system's backup policy was disabled to check for unauthorized changes that could reduce visibility into critical data protection and recovery capabilities, potentially hindering threat detection and compliance efforts."
  documentation   = file("./detections/docs/efs_file_system_backup_policy_disabled.md")
  severity        = "low"
  display_columns = local.detection_display_columns
  query           = query.efs_file_system_backup_policy_disabled

  tags = merge(local.efs_common_tags, {
    mitre_attack_ids = "TA0040:T1562.001"
  })
}

query "efs_file_system_backup_policy_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_file_system_id_or_mount_target_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name = 'PutBackupPolicy'
      and (request_parameters -> 'backupPolicy' ->> 'status') = 'DISABLED'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

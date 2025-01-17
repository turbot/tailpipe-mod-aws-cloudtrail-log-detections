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
    detection.efs_file_systems_backup_policy_disabled,
  ]

  tags = merge(local.efs_common_tags, {
    type = "Benchmark"
  })
}

detection "efs_file_systems_backup_policy_disabled" {
  title           = "EFS File Systems Backup Policy Disabled"
  description     = "Detect when EFS file systems backup policies were disabled to check for potential risks of data loss, unavailability, or non-compliance with backup and disaster recovery requirements."
  # documentation   = file("./detections/docs/detect_efs_file_systems_with_backup_policy_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.efs_file_systems_backup_policy_disabled

  tags = merge(local.efs_common_tags, {
    mitre_attack_ids = "TA0040:T1562.001"
  })
}

query "efs_file_systems_backup_policy_disabled" {
  sql = <<-EOQ
    select
      ${local.detection_sql_resource_column_request_parameters_file_system_id_or_mount_target_id}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name = 'PutBackupPolicy'
      and (request_parameters ->> 'BackupPolicyStatus') = 'DISABLED'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

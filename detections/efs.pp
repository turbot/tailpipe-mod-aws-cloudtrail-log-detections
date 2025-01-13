locals {
  efs_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EFS"
  })

  detect_efs_file_systems_with_backup_policy_disabled_sql_columns  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "coalesce(json_extract_string(request_parameters, '$.fileSystemId'), json_extract_string(request_parameters, '$.mountTargetId'))")
}

benchmark "efs_detections" {
  title       = "EFS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EFS events"
  type        = "detection"
  children    = [
    detection.detect_efs_file_systems_with_backup_policy_disabled,
  ]

  tags = merge(local.efs_common_tags, {
    type    = "Benchmark"
  })
}

detection "detect_efs_file_systems_with_backup_policy_disabled" {
  title           = "Detect EFS File Systems with Backup Policy Disabled"
  description     = "Identify events where backup policies are disabled for EFS file systems, potentially leaving data unprotected."
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.detect_efs_file_systems_with_backup_policy_disabled

  tags = merge(local.efs_common_tags, {
    mitre_attack_ids = "TA0040:T1562.001"
  })
}

query "detect_efs_file_systems_with_backup_policy_disabled" {
  sql = <<-EOQ
    select
      ${local.detect_efs_file_systems_with_backup_policy_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name = 'PutBackupPolicy'
      and json_extract_string(request_parameters, '$.BackupPolicyStatus') = 'DISABLED'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

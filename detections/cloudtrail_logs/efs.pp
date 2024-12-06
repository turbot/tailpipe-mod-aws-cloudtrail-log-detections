locals {
  cloudtrail_logs_detect_efs_deletion_updates_sql_columns                   = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "coalesce(request_parameters.fileSystemId, request_parameters.mountTargetId)")  
}

benchmark "cloudtrail_logs_efs_detections" {
  title       = "CloudTrail Log EFS Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EFS logs"
  type        = "detection"
  children    = [
    detection.cloudtrail_logs_detect_efs_deletion_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    type    = "Benchmark"
    service = "AWS/EFS"
  })
}

detection "cloudtrail_logs_detect_efs_deletion_updates" {
  title       = "Detect EFS Deletion Updates"
  description = "Detect EFS deletion events to monitor for unauthorized changes or potential disruptions. This includes tracking the deletion of file systems, mount targets, and related resources to ensure any unexpected activity is identified and addressed promptly."
  severity    = "medium"
  query       = query.cloudtrail_logs_detect_efs_deletion_updates

  tags = merge(local.cloudtrail_log_detection_common_tags, {
    mitre_attack_ids = ""
  })
}

query "cloudtrail_logs_detect_efs_deletion_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_efs_deletion_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'elasticfilesystem.amazonaws.com'
      and event_name in ('DeleteMountTarget', 'DeleteFileSystem', 'DeleteTags', 'DeleteFile', 'DeleteMountTargetSecurityGroups')
      and error_code is null
    order by
      event_time desc;
  EOQ
}
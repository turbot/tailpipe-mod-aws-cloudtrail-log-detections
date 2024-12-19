locals {
  cloudtrail_log_detection_ec2_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/EC2"
  })

  cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
  cloudtrail_logs_detect_ec2_ami_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_ec2_user_data_execution_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userData')")
  cloudtrail_logs_detect_ec2_instance_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.instancesSet.items')")
  cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.imageId')")
}

benchmark "cloudtrail_logs_ec2_detections" {
  title       = "EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EC2 events."
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_restore_image_task_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_store_image_tasks_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes,
    detection.cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled,
  ]

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled" {
  title           = "Detect EC2 Source/Destination Check Disabled"
  description     = "Identify attempts to disable the EC2 source/destination check, which could enable unauthorized traffic routing."
  severity        = "critical"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_instance_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifyInstanceAttribute'
      and json_extract_string(request_parameters, '$.attribute') = 'sourceDestCheck'
      and json_extract_string(request_parameters, '$.value') = 'false'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes" {
  title           = "Detect EC2 AMIs with Launch Permission Changes"
  description     = "Detect changes to EC2 AMI launch permissions to check for potential unauthorized access or privilege escalation."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_amis_with_launch_permission_changes_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('ResetImageAttribute')
      and json_extract_string(request_parameters, '$.attribute') = 'launchPermission'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts" {
  title           = "Detect EC2 AMIs Copied from External Accounts"
  description     = "Detect events where EC2 AMIs are copied across accounts to check for potential unauthorized duplication or data exfiltration."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CopyImage', 'CopyFpgaImage')
      and user_identity.account_id != json_extract_string(request_parameters, '$.SourceAccountId')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_restore_image_task_from_external_accounts" {
  title           = "Detect EC2 AMI Restore Image Task from External Accounts"
  description     = "Identify tasks to restore EC2 AMI images from different accounts, which could indicate unauthorized restoration or data recovery."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_restore_image_task_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0007:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_ami_restore_image_task_from_external_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateRestoreImageTask'
      and user_identity.account_id != json_extract_string(request_parameters, '$.OwnerId')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_store_image_tasks_from_external_accounts" {
  title           = "Detect EC2 AMI Store Image Tasks from External Accounts"
  description     = "Detect events where EC2 AMIs are stored in external accounts to check for potential data exfiltration or unauthorized usage."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_store_image_tasks_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "cloudtrail_logs_detect_ec2_ami_store_image_tasks_from_external_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateStoreImageTask'
      and user_identity.account_id != json_extract_string(request_parameters, '$.OwnerId')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts" {
  title           = "Detect EC2 AMI Imported from External Accounts"
  description     = "Identify events where AMIs are imported from external accounts, potentially introducing unauthorized or untrusted images."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0003:T1577"
  })
}

query "cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_ami_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ImportImage'
      and user_identity.account_id != json_extract_string(request_parameters, '$.OwnerId')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

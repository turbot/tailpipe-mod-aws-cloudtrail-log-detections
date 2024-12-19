locals {
  cloudtrail_log_detection_ec2_common_tags = merge(local.cloudtrail_log_detection_common_tags, {
    service = "AWS/EC2"
  })

  cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.snapshotId')")
  cloudtrail_logs_detect_ec2_ami_updates_sql_columns         = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.name')")
  cloudtrail_logs_detect_ec2_user_data_execution_sql_columns = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.userData')")
  cloudtrail_logs_detect_ec2_instance_updates_sql_columns    = replace(local.cloudtrail_log_detection_sql_columns, "__RESOURCE_SQL__", "json_extract_string(request_parameters, '$.instancesSet.items')")
}

benchmark "cloudtrail_logs_ec2_detections" {
  title       = "EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail's EC2 logs"
  type        = "detection"
  children = [
    detection.cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_imported_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_restored_tasks_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_ami_storage_tasks_created_from_external_accounts,
    detection.cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes,
    detection.cloudtrail_logs_detect_ec2_instances_with_source_dest_check_disabled,
    detection.cloudtrail_logs_detect_ec2_snapshot_updates,
  ]

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    type    = "Benchmark"
  })
}

detection "cloudtrail_logs_detect_ec2_snapshot_updates" {
  title           = "Detect EC2 Snapshots Updates"
  description     = "Detect EC2 snapshots updates to check for unauthorized changes."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_snapshot_updates

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = ""
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

detection "cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes" {
  title           = "Detect EC2 Launch Permission Changes"
  description     = "Identify changes to EC2 instance or AMI launch permissions, potentially granting unauthorized access."
  severity        = "medium"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_instances_with_launch_permission_changes" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_instance_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('ModifyInstanceAttribute', 'ResetImageAttribute')
      and json_extract_string(request_parameters, '$.attribute') = 'launchPermission'
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

query "cloudtrail_logs_detect_ec2_snapshot_updates" {
  sql = <<-EOQ
    select
      ${local.cloudtrail_logs_detect_ec2_snapshot_updates_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('DeleteSnapshot', 'ModifySnapshotAttribute')
      ${local.cloudtrail_log_detections_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "cloudtrail_logs_detect_ec2_ami_copied_from_external_accounts" {
  title           = "Detect Cross-Account EC2 AMI Copy Events"
  description     = "Identify events where EC2 AMIs are copied across accounts, which could indicate unauthorized duplication."
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

detection "cloudtrail_logs_detect_ec2_ami_restored_tasks_from_external_accounts" {
  title           = "Detect Cross-Account EC2 AMI Restore Tasks"
  description     = "Identify events where restore image tasks involve resources from different accounts, potentially indicating data recovery or unauthorized restoration."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_restored_tasks_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0007:T1078"
  })
}

query "cloudtrail_logs_detect_ec2_ami_restored_tasks_from_external_accounts" {
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

detection "cloudtrail_logs_detect_ec2_ami_storage_tasks_created_from_external_accounts" {
  title           = "Detect EC2 AMI Store Tasks in External Locations"
  description     = "Identify events where EC2 AMIs are stored in external or unapproved destinations, potentially indicating data exfiltration."
  severity        = "high"
  display_columns = local.cloudtrail_log_detection_display_columns
  query           = query.cloudtrail_logs_detect_ec2_ami_storage_tasks_created_from_external_accounts

  tags = merge(local.cloudtrail_log_detection_ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "cloudtrail_logs_detect_ec2_ami_storage_tasks_created_from_external_accounts" {
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
  title           = "Detect Cross-Account EC2 AMI Import Events"
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

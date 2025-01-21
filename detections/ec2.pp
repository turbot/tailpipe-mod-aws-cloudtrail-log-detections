locals {
  ec2_common_tags = merge(local.aws_cloudtrail_log_detections_common_tags, {
    service = "AWS/EC2"
  })

  ec2_instance_user_data_modified_with_ssh_key_addition_sql_columns = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'userData'")
  ec2_instance_updates_sql_columns                                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'instanceId'")
  ec2_ami_launch_permission_updated_sql_columns                     = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'imageId'")
  ec2_ami_copied_from_external_account_sql_columns                  = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'sourceImageId'")
  ec2_ami_imported_from_external_account_sql_columns                = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'imageId'")
  ec2_ami_restore_image_task_from_external_account_sql_columns      = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'sourceImageId'")
  ec2_ami_store_image_task_from_external_account_sql_columns        = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'sourceImageId'")
  ec2_instance_source_dest_check_disabled_sql_columns               = replace(local.detection_sql_columns, "__RESOURCE_SQL__", "request_parameters ->> 'instanceId'")
}

benchmark "ec2_detections" {
  title       = "EC2 Detections"
  description = "This benchmark contains recommendations when scanning CloudTrail logs for EC2 events."
  type        = "detection"
  children = [
    detection.ec2_ami_copied_from_external_account,
    detection.ec2_ami_imported_from_external_account,
    detection.ec2_ami_restore_image_task_from_external_account,
    detection.ec2_ami_store_image_task_from_external_account,
    detection.ec2_ami_launch_permission_updated,
    detection.ec2_instance_source_dest_check_disabled,
    detection.ec2_instance_user_data_modified_with_ssh_key_addition,
  ]

  tags = merge(local.ec2_common_tags, {
    type = "Benchmark"
  })
}

detection "ec2_instance_source_dest_check_disabled" {
  title           = "EC2 Instance Source/Destination Check Disabled"
  description     = "Detect when the source/destination check was disabled for an EC2 instance. Disabling this check could have allowed unauthorized traffic routing, potentially enabling a malicious activity such as a man-in-the-middle attack or lateral movement."
  documentation   = file("./detections/docs/ec2_instance_source_dest_check_disabled.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ec2_instance_source_dest_check_disabled

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1562.001"
  })
}

query "ec2_instance_source_dest_check_disabled" {
  sql = <<-EOQ
    select
      ${local.ec2_instance_source_dest_check_disabled_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifyInstanceAttribute'
      and (request_parameters ->> 'attribute') = 'sourceDestCheck'
      and (request_parameters -> 'value') = false
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_instance_user_data_modified_with_ssh_key_addition" {
  title           = "EC2 Instance User Data Modified with SSH Key Addition"
  description     = "Detect when the user data of an EC2 instance was modified to include an SSH key addition. This modification could indicate unauthorized access attempts or compromise."
  documentation   = file("./detections/docs/ec2_instance_user_data_modified_with_ssh_key_addition.md")
  severity        = "critical"
  display_columns = local.detection_display_columns
  query           = query.ec2_instance_user_data_modified_with_ssh_key_addition

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0003:T1098.004"
  })
}

query "ec2_instance_user_data_modified_with_ssh_key_addition" {
  sql = <<-EOQ
    select
      ${local.ec2_instance_user_data_modified_with_ssh_key_addition_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ModifyInstanceAttribute'
      and (request_parameters -> 'attributeName') = 'userData'
      and (request_parameters -> 'value') like '%ssh-rsa%'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}


detection "ec2_ami_launch_permission_updated" {
  title           = "EC2 AMI Launch Permission Updated"
  description     = "Detect when an EC2 AMI launch permission was updated. Modifying a launch permission may have allowed unauthorized access or privilege escalation, potentially exposing a sensitive resource."
  documentation   = file("./detections/docs/ec2_ami_launch_permission_updated.md")
  severity        = "medium"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_launch_permission_updated

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0005:T1078"
  })
}

query "ec2_ami_launch_permission_updated" {
  sql = <<-EOQ
    select
      ${local.ec2_ami_launch_permission_updated_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ResetImageAttribute'
      and (request_parameters ->> 'attribute') = 'launchPermission'
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_ami_copied_from_external_account" {
  title           = "EC2 AMI Copied from External Account"
  description     = "Detect when an EC2 AMI was copied from an external account. This could indicate potential unauthorized duplication or data exfiltration."
  documentation   = file("./detections/docs/ec2_ami_copied_from_external_account.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_copied_from_external_account

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1020"
  })
}

query "ec2_ami_copied_from_external_account" {
  sql = <<-EOQ
    select
      ${local.ec2_ami_copied_from_external_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name in ('CopyImage', 'CopyFpgaImage')
      and (user_identity ->> 'accountId') != (request_parameters ->> 'SourceAccountId')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_ami_restore_image_task_from_external_account" {
  title           = "EC2 AMI Restore Image Task from External Account"
  description     = "Detect when an EC2 AMI restore image task was created from a different account. This action could indicate unauthorized restoration or data recovery, potentially exposing sensitive data."
  documentation   = file("./detections/docs/ec2_ami_restore_image_task_from_external_account.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_restore_image_task_from_external_account

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0007:T1078"
  })
}

query "ec2_ami_restore_image_task_from_external_account" {
  sql = <<-EOQ
    select
      ${local.ec2_ami_restore_image_task_from_external_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateRestoreImageTask'
      and (user_identity ->> 'accountId') != (request_parameters ->> 'OwnerId')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_ami_store_image_task_from_external_account" {
  title           = "EC2 AMI Store Image Task from External Account"
  description     = "Detect when an EC2 AMI store image task was created for an external account. This action could indicate potential data exfiltration or unauthorized usage of an AMI."
  documentation   = file("./detections/docs/ec2_ami_store_image_task_from_external_account.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_store_image_task_from_external_account

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0010:T1537"
  })
}

query "ec2_ami_store_image_task_from_external_account" {
  sql = <<-EOQ
    select
      ${local.ec2_ami_store_image_task_from_external_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'CreateStoreImageTask'
      and (user_identity ->> 'accountId') != (request_parameters ->> 'OwnerId')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

detection "ec2_ami_imported_from_external_account" {
  title           = "EC2 AMI Imported from External Account"
  description     = "Detect when an EC2 AMI was imported from an external account. Importing AMIs from external accounts may introduce untrusted or unauthorized images, potentially leading to security vulnerabilities."
  documentation   = file("./detections/docs/ec2_ami_imported_from_external_account.md")
  severity        = "high"
  display_columns = local.detection_display_columns
  query           = query.ec2_ami_imported_from_external_account

  tags = merge(local.ec2_common_tags, {
    mitre_attack_ids = "TA0003:T1577"
  })
}

query "ec2_ami_imported_from_external_account" {
  sql = <<-EOQ
    select
      ${local.ec2_ami_imported_from_external_account_sql_columns}
    from
      aws_cloudtrail_log
    where
      event_source = 'ec2.amazonaws.com'
      and event_name = 'ImportImage'
      and (user_identity ->> 'accountId') != (request_parameters ->> 'OwnerId')
      ${local.detection_sql_where_conditions}
    order by
      event_time desc;
  EOQ
}

